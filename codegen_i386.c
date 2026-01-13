#include "chibicc.h"

// i386 (SysV cdecl) code generator.
//
// Current scope (initial bring-up):
// - Integer + pointer codegen (<= 4 bytes) and basic control flow
// - Function calls via stack arguments (cdecl)
//
// Not supported yet (will error):
// - Floating point (float/double/long double)
// - 64-bit integer arithmetic (long long)
// - Struct/union args and returns
// - Atomics / CAS / EXCH

static FILE *output_file;
static int depth;
static Obj *current_fn;

__attribute__((format(printf, 1, 2)))
static void println(char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(output_file, fmt, ap);
  va_end(ap);
  fprintf(output_file, "\n");
}

static int count(void) {
  static int i = 1;
  return i++;
}

static void push(void) {
  println("  push %%eax");
  depth++;
}

static void pop(char *arg) {
  println("  pop %s", arg);
  depth--;
}

static void pushf(void) {
  // Spill ST(0) to the integer stack as a double and pop it.
  println("  sub $8, %%esp");
  println("  fstpl (%%esp)");
  depth += 2;
}

static void popf(void) {
  // Load a double from the integer stack into x87, then pop the integer stack.
  println("  fldl (%%esp)");
  println("  add $8, %%esp");
  depth -= 2;
}

static void gen_expr(Node *node);
static void gen_stmt(Node *node);

static void unreachable_i386(Token *tok, char *msg) {
  if (tok)
    error_tok(tok, "i386 backend: %s", msg);
  error("i386 backend: %s", msg);
}

static void assert_i386_scalar(Type *ty, Token *tok) {
  if (ty->kind == TY_LDOUBLE)
    unreachable_i386(tok, "long double not supported yet");
  // `double` is 8 bytes; allow that. Reject 64-bit integers (e.g., long long).
  if (ty->size == 8 && !is_flonum(ty))
    unreachable_i386(tok, "64-bit integers not supported yet");
  if (ty->kind == TY_STRUCT || ty->kind == TY_UNION)
    unreachable_i386(tok, "struct/union values not supported yet");
}

static void gen_addr(Node *node) {
  switch (node->kind) {
  case ND_VAR:
    if (node->var->is_local) {
      println("  lea %d(%%ebp), %%eax", node->var->offset);
      return;
    }
    println("  mov $%s, %%eax", node->var->name);
    return;
  case ND_DEREF:
    gen_expr(node->lhs);
    return;
  case ND_MEMBER:
    gen_addr(node->lhs);
    println("  add $%d, %%eax", node->member->offset);
    return;
  case ND_COMMA:
    gen_expr(node->lhs);
    gen_addr(node->rhs);
    return;
  default:
    break;
  }

  error_tok(node->tok, "not an lvalue");
}

static void load(Type *ty) {
  if (ty->kind == TY_ARRAY || ty->kind == TY_STRUCT || ty->kind == TY_UNION)
    return;

  if (ty->kind == TY_LDOUBLE)
    error("i386 backend: long double load not supported");

  if (is_flonum(ty)) {
    if (ty->kind == TY_FLOAT)
      println("  flds (%%eax)");
    else
      println("  fldl (%%eax)");
    return;
  }

  if (ty->size == 1) {
    if (ty->is_unsigned)
      println("  movzbl (%%eax), %%eax");
    else
      println("  movsbl (%%eax), %%eax");
    return;
  }

  if (ty->size == 2) {
    if (ty->is_unsigned)
      println("  movzwl (%%eax), %%eax");
    else
      println("  movswl (%%eax), %%eax");
    return;
  }

  if (ty->size == 4) {
    println("  mov (%%eax), %%eax");
    return;
  }

  if (ty->size == 8)
    error("i386 backend: 64-bit load not supported");

  error("internal error: invalid type size");
}

static void store(Type *ty) {
  pop("%ecx"); // address

  if (ty->kind == TY_STRUCT || ty->kind == TY_UNION) {
    // For aggregates, `gen_expr(rhs)` leaves the source address in %eax.
    // Copy ty->size bytes from %eax -> %ecx.
    println("  mov %%ecx, %%edx"); // save dst
    println("  mov %%eax, %%esi"); // src
    println("  mov %%edx, %%edi"); // dst
    println("  mov $%d, %%ecx", ty->size);
    println("  rep movsb");
    // Assignment expression value becomes the destination address.
    println("  mov %%edx, %%eax");
    return;
  }

  if (ty->kind == TY_LDOUBLE)
    error("i386 backend: long double store not supported");

  if (is_flonum(ty)) {
    // Store ST(0) to *addr without popping (so assignment can be an expression).
    if (ty->kind == TY_FLOAT)
      println("  fsts (%%ecx)");
    else
      println("  fstl (%%ecx)");
    return;
  }

  if (ty->size == 1) {
    println("  mov %%al, (%%ecx)");
    return;
  }

  if (ty->size == 2) {
    println("  mov %%ax, (%%ecx)");
    return;
  }

  if (ty->size == 4) {
    println("  mov %%eax, (%%ecx)");
    return;
  }

  error("i386 backend: unsupported store size");
}

static void cmp_zero(Type *ty) {
  assert_i386_scalar(ty, NULL);
  if (is_flonum(ty)) {
    // Compare ST(0) with 0.0, set FLAGS, then pop the value (conditions discard).
    println("  ftst");
    println("  fnstsw %%ax");
    println("  sahf");
    println("  fstp %%st(0)");
    return;
  }
  println("  cmp $0, %%eax");
}

static void cast_i386(Type *from, Type *to) {
  if (to->kind == TY_VOID)
    return;

  if (to->kind == TY_BOOL) {
    cmp_zero(from);
    println("  setne %%al");
    println("  movzbl %%al, %%eax");
    return;
  }

  if (from->kind == TY_LDOUBLE || to->kind == TY_LDOUBLE)
    error("i386 backend: long double casts not supported");

  // Integer <-> float/double casts.
  if (!is_flonum(from) && is_flonum(to)) {
    // EAX -> ST(0)
    println("  sub $4, %%esp");
    println("  mov %%eax, (%%esp)");
    println("  fildl (%%esp)");
    println("  add $4, %%esp");
    return;
  }

  if (is_flonum(from) && !is_flonum(to)) {
    // ST(0) -> EAX (truncate toward zero by temporarily changing RC bits).
    // Note: only supports 32-bit integer destinations for now.
    if (to->size != 4)
      error("i386 backend: float->int cast only supports 32-bit destinations");

    println("  sub $8, %%esp");
    println("  fnstcw 4(%%esp)");
    println("  movw 4(%%esp), %%cx");
    println("  orw $0x0C00, %%cx");
    println("  movw %%cx, 6(%%esp)");
    println("  fldcw 6(%%esp)");
    println("  fistpl (%%esp)");
    println("  fldcw 4(%%esp)");
    println("  mov (%%esp), %%eax");
    println("  add $8, %%esp");

    // If target is smaller than 32-bit, we'll fall through to the integer
    // narrowing below.
    from = ty_int;
  }

  // Float<->float: no-op (x87 keeps values in ST(0) and stores will round).
  if (is_flonum(from) && is_flonum(to))
    return;

  // Pointer/integer casts: we only support <= 32-bit values for now.
  if (to->size == 1) {
    if (to->is_unsigned)
      println("  movzbl %%al, %%eax");
    else
      println("  movsbl %%al, %%eax");
    return;
  }

  if (to->size == 2) {
    if (to->is_unsigned)
      println("  movzwl %%ax, %%eax");
    else
      println("  movswl %%ax, %%eax");
    return;
  }

  // to->size == 4: no-op
  if (to->size != 4)
    error("i386 backend: unsupported cast size");
}

static void gen_expr(Node *node) {
  switch (node->kind) {
  case ND_NULL_EXPR:
    return;

  case ND_NUM:
    switch (node->ty->kind) {
    case TY_FLOAT: {
      union { float f32; uint32_t u32; } u = { (float)node->fval };
      println("  sub $4, %%esp");
      println("  movl $%u, (%%esp)", u.u32);
      println("  flds (%%esp)");
      println("  add $4, %%esp");
      return;
    }
    case TY_DOUBLE: {
      union { double f64; uint64_t u64; } u = { (double)node->fval };
      uint32_t lo = (uint32_t)(u.u64 & 0xffffffffu);
      uint32_t hi = (uint32_t)(u.u64 >> 32);
      println("  sub $8, %%esp");
      println("  movl $%u, (%%esp)", lo);
      println("  movl $%u, 4(%%esp)", hi);
      println("  fldl (%%esp)");
      println("  add $8, %%esp");
      return;
    }
    case TY_LDOUBLE:
      unreachable_i386(node->tok, "long double literal not supported yet");
    default:
      break;
    }

    println("  mov $%ld, %%eax", node->val);
    return;

  case ND_NEG:
    gen_expr(node->lhs);
    if (is_flonum(node->ty)) {
      println("  fchs");
      return;
    }
    println("  neg %%eax");
    return;

  case ND_VAR:
    gen_addr(node);
    load(node->ty);
    return;

  case ND_MEMBER:
    gen_addr(node);
    load(node->ty);
    return;

  case ND_ADDR:
    gen_addr(node->lhs);
    return;

  case ND_DEREF:
    gen_expr(node->lhs);
    load(node->ty);
    return;

  case ND_ASSIGN:
    gen_addr(node->lhs);
    push();
    gen_expr(node->rhs);
    store(node->ty);
    return;

  case ND_STMT_EXPR:
    for (Node *n = node->body; n; n = n->next)
      gen_stmt(n);
    return;

  case ND_COMMA:
    gen_expr(node->lhs);
    if (node->lhs && node->lhs->ty && is_flonum(node->lhs->ty))
      println("  fstp %%st(0)");
    gen_expr(node->rhs);
    return;

  case ND_CAST:
    // For now, only support integer/pointer casts up to 32-bit.
    gen_expr(node->lhs);
    cast_i386(node->lhs->ty, node->ty);
    return;

  case ND_MEMZERO:
    // rep stosb: memset(%edi, %al, %ecx)
    println("  mov $%d, %%ecx", node->var->ty->size);
    println("  lea %d(%%ebp), %%edi", node->var->offset);
    println("  mov $0, %%al");
    println("  rep stosb");
    return;

  case ND_EQ:
  case ND_NE:
  case ND_LT:
  case ND_LE:
  case ND_ADD:
  case ND_SUB:
  case ND_MUL:
  case ND_DIV:
  case ND_MOD:
  case ND_BITAND:
  case ND_BITOR:
  case ND_BITXOR:
  case ND_SHL:
  case ND_SHR: {
    assert_i386_scalar(node->ty, node->tok);

    if (is_flonum(node->lhs->ty) || is_flonum(node->rhs->ty)) {
      if (node->kind == ND_MOD || node->kind == ND_BITAND || node->kind == ND_BITOR ||
          node->kind == ND_BITXOR || node->kind == ND_SHL || node->kind == ND_SHR)
        error_tok(node->tok, "i386 backend: operator not supported for floating point");

      // Evaluate lhs, spill, evaluate rhs, then reload lhs so x87 stack has:
      //   ST(0)=lhs, ST(1)=rhs
      gen_expr(node->lhs);
      pushf();
      gen_expr(node->rhs);
      popf();

      if (node->kind == ND_ADD) {
        println("  faddp %%st, %%st(1)");
        return;
      }
      if (node->kind == ND_SUB) {
        // With our stack layout (ST0=lhs, ST1=rhs), plain fsubp computes lhs-rhs.
        // (The *rp variants reverse the operation; avoid them.)
        println("  fsubp %%st, %%st(1)");
        return;
      }
      if (node->kind == ND_MUL) {
        println("  fmulp %%st, %%st(1)");
        return;
      }
      if (node->kind == ND_DIV) {
        // With our stack layout (ST0=lhs, ST1=rhs), plain fdivp computes lhs/rhs.
        // (The *rp variants reverse the operation; avoid them.)
        println("  fdivp %%st, %%st(1)");
        return;
      }

      // Comparisons: pop both operands and set EAX to 0/1.
      // After `fucompp`:
      //   C3->ZF, C2->PF (unordered), C0->CF.
      println("  fucompp");
      println("  fnstsw %%ax");
      println("  sahf");

      if (node->kind == ND_EQ) {
        println("  sete %%al");
      } else if (node->kind == ND_NE) {
        println("  setne %%al");
      } else if (node->kind == ND_LT) {
        println("  setb %%al");
      } else if (node->kind == ND_LE) {
        println("  setbe %%al");
      } else {
        unreachable();
      }

      println("  movzbl %%al, %%eax");
      return;
    }

    gen_expr(node->rhs);
    push();
    gen_expr(node->lhs);
    pop("%ecx");

    switch (node->kind) {
    case ND_ADD:
      println("  add %%ecx, %%eax");
      return;
    case ND_SUB:
      println("  sub %%ecx, %%eax");
      return;
    case ND_MUL:
      println("  imul %%ecx, %%eax");
      return;
    case ND_DIV:
    case ND_MOD:
      // eax = lhs, ecx = rhs
      if (node->ty->is_unsigned) {
        println("  xor %%edx, %%edx");
        println("  div %%ecx");
      } else {
        println("  mov %%eax, %%edx");
        println("  sar $31, %%edx");
        println("  idiv %%ecx");
      }
      if (node->kind == ND_MOD)
        println("  mov %%edx, %%eax");
      return;
    case ND_BITAND:
      println("  and %%ecx, %%eax");
      return;
    case ND_BITOR:
      println("  or %%ecx, %%eax");
      return;
    case ND_BITXOR:
      println("  xor %%ecx, %%eax");
      return;
    case ND_SHL:
      println("  shl %%cl, %%eax");
      return;
    case ND_SHR:
      if (node->ty->is_unsigned)
        println("  shr %%cl, %%eax");
      else
        println("  sar %%cl, %%eax");
      return;
    case ND_EQ:
    case ND_NE:
    case ND_LT:
    case ND_LE:
      println("  cmp %%ecx, %%eax");
      if (node->kind == ND_EQ)
        println("  sete %%al");
      else if (node->kind == ND_NE)
        println("  setne %%al");
      else if (node->kind == ND_LT)
        println("  %s %%al", node->lhs->ty->is_unsigned ? "setb" : "setl");
      else
        println("  %s %%al", node->lhs->ty->is_unsigned ? "setbe" : "setle");
      println("  movzbl %%al, %%eax");
      return;
    default:
      break;
    }
    unreachable();
  }

  case ND_NOT:
    gen_expr(node->lhs);
    cmp_zero(node->lhs->ty);
    println("  sete %%al");
    println("  movzbl %%al, %%eax");
    return;

  case ND_BITNOT:
    gen_expr(node->lhs);
    println("  not %%eax");
    return;

  case ND_LOGAND: {
    int c = count();
    gen_expr(node->lhs);
    cmp_zero(node->lhs->ty);
    println("  je  .L.false.%d", c);
    gen_expr(node->rhs);
    cmp_zero(node->rhs->ty);
    println("  je  .L.false.%d", c);
    println("  mov $1, %%eax");
    println("  jmp .L.end.%d", c);
    println(".L.false.%d:", c);
    println("  mov $0, %%eax");
    println(".L.end.%d:", c);
    return;
  }

  case ND_LOGOR: {
    int c = count();
    gen_expr(node->lhs);
    cmp_zero(node->lhs->ty);
    println("  jne .L.true.%d", c);
    gen_expr(node->rhs);
    cmp_zero(node->rhs->ty);
    println("  jne .L.true.%d", c);
    println("  mov $0, %%eax");
    println("  jmp .L.end.%d", c);
    println(".L.true.%d:", c);
    println("  mov $1, %%eax");
    println(".L.end.%d:", c);
    return;
  }

  case ND_COND: {
    int c = count();
    gen_expr(node->cond);
    cmp_zero(node->cond->ty);
    println("  je  .L.else.%d", c);
    gen_expr(node->then);
    println("  jmp .L.end.%d", c);
    println(".L.else.%d:", c);
    gen_expr(node->els);
    println(".L.end.%d:", c);
    return;
  }

  case ND_FUNCALL: {
    // Evaluate arguments right-to-left and push.
    // For cdecl, by-value structs/unions are passed by copying bytes onto the stack.
    int stack_bytes = 0;
    int nargs = 0;
    for (Node *arg = node->args; arg; arg = arg->next)
      nargs++;

    Node **argv = calloc(nargs, sizeof(Node *));
    int idx = 0;
    for (Node *arg = node->args; arg; arg = arg->next)
      argv[idx++] = arg;

    for (int i = nargs - 1; i >= 0; i--) {
      Node *arg = argv[i];
      Type *ty = arg->ty;

      if (ty->kind == TY_STRUCT || ty->kind == TY_UNION) {
        gen_expr(arg); // %eax = source address
        int sz = align_to(ty->size, 4);
        println("  sub $%d, %%esp", sz);
        println("  mov %%esp, %%edi");
        println("  mov %%eax, %%esi");
        println("  mov $%d, %%ecx", ty->size);
        println("  rep movsb");
        stack_bytes += sz;
        depth += sz / 4;
        continue;
      }

      if (ty->kind == TY_LDOUBLE)
        error_tok(arg->tok, "i386 backend: long double args not supported");

      if (is_flonum(ty)) {
        gen_expr(arg); // ST(0)
        // Pass float/double by value on the stack.
        if (ty->kind == TY_FLOAT) {
          println("  sub $4, %%esp");
          println("  fstps (%%esp)");
          stack_bytes += 4;
          depth++;
        } else {
          println("  sub $8, %%esp");
          println("  fstpl (%%esp)");
          stack_bytes += 8;
          depth += 2;
        }
        continue;
      }

      assert_i386_scalar(ty, arg->tok);
      gen_expr(arg);
      println("  push %%eax");
      stack_bytes += 4;
      depth++;
    }

    free(argv);

    // If a function returns a struct/union, pass a pointer to a caller-allocated
    // return buffer as the hidden first argument.
    if (node->ret_buffer && (node->ty->kind == TY_STRUCT || node->ty->kind == TY_UNION)) {
      println("  lea %d(%%ebp), %%eax", node->ret_buffer->offset);
      println("  push %%eax");
      stack_bytes += 4;
      depth++;
    }

    if (node->lhs->kind == ND_VAR && node->lhs->var && node->lhs->var->is_function) {
      // Direct call to a known function symbol.
      println("  call %s", node->lhs->var->name);
    } else {
      // Indirect call (e.g., function pointer variable/parameter or expression).
      gen_expr(node->lhs);
      println("  call *%%eax");
    }

    if (stack_bytes) {
      println("  add $%d, %%esp", stack_bytes);
      depth -= stack_bytes / 4;
    }

    // For struct/union returns, the value is in the return buffer.
    if (node->ret_buffer && (node->ty->kind == TY_STRUCT || node->ty->kind == TY_UNION))
      println("  lea %d(%%ebp), %%eax", node->ret_buffer->offset);

    // For float/double returns (cdecl), the value is in ST(0).

    return;
  }

  default:
    break;
  }

  error_tok(node->tok, "i386 backend: unsupported expression");
}

static void gen_stmt(Node *node) {
  switch (node->kind) {
  case ND_RETURN:
    if (node->lhs) {
      Type *rty = current_fn->ty->return_ty;
      if (rty->kind == TY_STRUCT || rty->kind == TY_UNION) {
        // Return aggregates via hidden sret pointer (first parameter).
        // node->lhs evaluates to the source address in %eax.
        gen_expr(node->lhs);
        Obj *sret = current_fn->params;
        if (!sret)
          unreachable_i386(node->tok, "missing sret parameter");
        println("  mov %d(%%ebp), %%edx", sret->offset);
        println("  mov %%eax, %%esi");
        println("  mov %%edx, %%edi");
        println("  mov $%d, %%ecx", rty->size);
        println("  rep movsb");
        // GCC-style: also return the sret pointer in %eax.
        println("  mov %%edx, %%eax");
      } else {
        gen_expr(node->lhs);
      }
    }
    println("  jmp .L.return.%s", current_fn->name);
    return;

  case ND_EXPR_STMT:
    gen_expr(node->lhs);
    if (node->lhs && node->lhs->ty && is_flonum(node->lhs->ty))
      println("  fstp %%st(0)");
    return;

  case ND_BLOCK:
    for (Node *n = node->body; n; n = n->next)
      gen_stmt(n);
    return;

  case ND_DO: {
    int c = count();
    println(".L.begin.%d:", c);
    gen_stmt(node->then);
    println("%s:", node->cont_label);
    gen_expr(node->cond);
    cmp_zero(node->cond->ty);
    println("  jne .L.begin.%d", c);
    println("%s:", node->brk_label);
    return;
  }

  case ND_SWITCH:
    // Evaluate switch condition into %eax.
    gen_expr(node->cond);
    assert_i386_scalar(node->cond->ty, node->tok);

    for (Node *n = node->case_next; n; n = n->case_next) {
      // Current i386 backend only supports <= 32-bit integer switch values.
      // (64-bit integer codegen is a separate feature.)
      if (n->begin == n->end) {
        println("  cmp $%ld, %%eax", n->begin);
        println("  je %s", n->label);
        continue;
      }

      // [GNU] Case ranges: if (begin <= eax && eax <= end) goto label.
      println("  mov %%eax, %%edi");
      println("  sub $%ld, %%edi", n->begin);
      println("  cmp $%ld, %%edi", n->end - n->begin);
      println("  jbe %s", n->label);
    }

    if (node->default_case)
      println("  jmp %s", node->default_case->label);

    println("  jmp %s", node->brk_label);
    gen_stmt(node->then);
    println("%s:", node->brk_label);
    return;

  case ND_CASE:
    println("%s:", node->label);
    gen_stmt(node->lhs);
    return;

  case ND_IF: {
    int c = count();
    gen_expr(node->cond);
    cmp_zero(node->cond->ty);
    println("  je  .L.else.%d", c);
    gen_stmt(node->then);
    println("  jmp .L.end.%d", c);
    println(".L.else.%d:", c);
    if (node->els)
      gen_stmt(node->els);
    println(".L.end.%d:", c);
    return;
  }

  case ND_FOR: {
    int c = count();
    if (node->init)
      gen_stmt(node->init);
    println(".L.begin.%d:", c);
    if (node->cond) {
      gen_expr(node->cond);
      cmp_zero(node->cond->ty);
      println("  je %s", node->brk_label);
    }
    gen_stmt(node->then);
    println("%s:", node->cont_label);
    if (node->inc)
      gen_expr(node->inc);
    println("  jmp .L.begin.%d", c);
    println("%s:", node->brk_label);
    return;
  }

  case ND_GOTO:
    println("  jmp %s", node->unique_label);
    return;

  case ND_LABEL:
    println("%s:", node->unique_label);
    gen_stmt(node->lhs);
    return;

  case ND_ASM:
    println("  %s", node->asm_str);
    return;

  case ND_CAS:
  case ND_EXCH:
    error_tok(node->tok, "i386 backend: statement kind not supported yet");

  default:
    break;
  }

  error_tok(node->tok, "i386 backend: unsupported statement");
}

static void assign_lvar_offsets_i386(Obj *prog) {
  for (Obj *fn = prog; fn; fn = fn->next) {
    if (!fn->is_function)
      continue;

    // cdecl: return address at +4, first arg at +8.
    int top = 8;
    int bottom = 0;

    for (Obj *var = fn->params; var; var = var->next) {
      int sz = align_to(var->ty->size, 4);
      var->offset = top;
      top += sz;
    }

    for (Obj *var = fn->locals; var; var = var->next) {
      if (var->offset)
        continue;
      bottom += var->ty->size;
      bottom = align_to(bottom, MAX(4, var->align));
      var->offset = -bottom;
    }

    fn->stack_size = align_to(bottom, 16);
  }
}

static void emit_data_i386(Obj *prog) {
  // Reuse the existing data emission logic: it is target-agnostic.
  // This emits .data/.bss/.comm and string literals.
  //
  // We call into the x86-64 codegen's emit_data by duplicating its minimal behavior.
  for (Obj *var = prog; var; var = var->next) {
    if (var->is_function || !var->is_definition)
      continue;

    if (var->is_static)
      println("  .local %s", var->name);
    else
      println("  .globl %s", var->name);

    int align = var->align;

    if (opt_fcommon && var->is_tentative) {
      println("  .comm %s, %d, %d", var->name, var->ty->size, align);
      continue;
    }

    if (var->init_data) {
      println("  .data");
      println("  .type %s, @object", var->name);
      println("  .size %s, %d", var->name, var->ty->size);
      println("  .align %d", align);
      println("%s:", var->name);

      int pos = 0;
      Relocation *rel = var->rel;
      while (pos < var->ty->size) {
        if (rel && rel->offset == pos) {
          println("  .long %s%+ld", *rel->label, rel->addend);
          rel = rel->next;
          pos += 4;
          continue;
        }

        println("  .byte %d", (unsigned char)var->init_data[pos]);
        pos++;
      }
      continue;
    }

    // .bss
    println("  .bss");
    println("  .align %d", align);
    println("%s:", var->name);
    println("  .zero %d", var->ty->size);
  }
}

static void emit_text_i386(Obj *prog) {
  for (Obj *fn = prog; fn; fn = fn->next) {
    if (!fn->is_function || !fn->is_definition)
      continue;

    current_fn = fn;

    if (fn->is_static)
      println("  .local %s", fn->name);
    else
      println("  .globl %s", fn->name);

    println("  .text");
    println("  .type %s, @function", fn->name);
    println("%s:", fn->name);

    // Prologue
    println("  push %%ebp");
    println("  mov %%esp, %%ebp");
    println("  sub $%d, %%esp", fn->stack_size);

    depth = 0;

    // Emit body
    gen_stmt(fn->body);

    // Implicit return 0 from main.
    if (strcmp(fn->name, "main") == 0)
      println("  mov $0, %%eax");

    // Epilogue
    println(".L.return.%s:", fn->name);
    println("  mov %%ebp, %%esp");
    println("  pop %%ebp");
    println("  ret");
  }
}

void codegen_i386(Obj *prog, FILE *out) {
  output_file = out;

  File **files = get_input_files();
  for (int i = 0; files[i]; i++)
    println("  .file %d \"%s\"", files[i]->file_no, files[i]->name);

  assign_lvar_offsets_i386(prog);
  emit_data_i386(prog);
  emit_text_i386(prog);
}
