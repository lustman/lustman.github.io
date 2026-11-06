---
layout: post
title: "A quick guide to decrypting strings in ArmDot v2026"
---

Analysis of string encryption in ArmDot v2026.6.

## Theory

Encrypted data is written to PE as a raw block using the `.data` directive.
A separate structure type with a static field is generated to access the block:
```csharp
[StructLayout(LayoutKind.Explicit, Pack = 1, Size = N)]
internal struct <StructName>
{
    // Note: this field is marked with 'hasfieldrva'.
    internal static readonly <StructName> <FieldName>;
}
```

In IL:
```
.class private explicit ansi sealed <StructName>
    extends [System.Runtime]System.ValueType
{
    .pack 1
    .size N

    .field assembly static initonly valuetype <StructName>
        <FieldName> at I_0000xxxx
}

.data cil I_0000xxxx = bytearray (
    ...
)
```

### Typed wrapper over bytes

It is not a structure in the usual meaning, but rather a typed wrapper over bytes that are physically located in the build image.
The field has the `HasFieldRVA` flag, and the metadata contains a corresponding entry in the `FieldRVA` table - a `Field -> RVA` pair that links the field to its source data.
`Pack = 1` disables additional field alignment, and `Size = N` specifies the size of the structure.

### Inline decryptor

A decryptor is embedded in place of the original `ldstr`. It allocates a `char[]`, fills it with the decrypted characters, and passes it to the `System.String` constructor:
```csharp
char[] array = (obj = new char[N]);
obj[0] = ...;
obj[1] = ...;
// ...
obj[N - 1] = ...;

string result = new string(array);
```

The array declaration in IL looks like this:
```
ldc.i4    N
newarr    [System.Runtime]System.Char
dup
stloc     V_xxx
```

Reference to the array stays on the stack and is simultaneously stored in the local variable `V_xxx`. That's why the decompiler can represent a single array using two variables: `obj` and `array`.

### Operand sources

For each character, the protector generates an expression with `^`. There are 2 operand sources, based on the selected option:

- Constant: `obj[i] = c0 ^ c1`. Both operands are represented by literal values using `ldc.i4`.
- Field-based: `obj[i] = field0[offset] ^ c1`. One operand is retrieved from an RVA block via a pointer; the second is specified by a constant.

As a result, the same decryptor can contain both entirely constant expressions and references to data within the PE.
Since the option is selected separately for each character, some bytes of the RVA block may not be read at all. In such cases, data not involved in string reconstruction remains in the block.

## RVA access

The most interesting part of the design is reading a byte from an RVA block:
```
ldsflda  valuetype <T> <T>::field0
conv.i
ldc.i4   N
add
ldind.u1
```

### The FieldRVA mechanism

Where does the memory used for address arithmetic come from?

The mechanism is called `FieldRVA`. The metadata contains a separate `FieldRVA` table with two columns: `Rva` and `Field`. Each entry associates a static field with the initial data located at a specific RVA.
The `HasFieldRVA` flag in the `Field` table indicates the presence of a corresponding entry. The data itself is placed in a section of the image during PE assembly.
When loading the assembly, the CLR uses this information to provide the static field with access to the initial data block.

### Analysis of the instruction sequence

The instruction sequence is analyzed as follows:

- `ldsflda` - loads the address of a static field.
- `conv.i` - converts the address to a native int.
- `ldc.i4 N; add` - adds an offset to the address.
- `ldind.u1` - reads one byte from the resulting address.
- `conv.i4` - converts the value to an `int32` if required by subsequent instructions.
- `ldc.i4 key; xor` - performs an XOR operation with the key.
- `stelem.i2` - writes the result to an element of `char[]`.

The last instruction writes 2 bytes as `System.Char` in .NET is represented by a 16 bit value.

### Example from a real build

Let's take a snippet from a real build protected by ArmDot. The decompiler shows:
```csharp
char[] array9 = (obj = new char[21]);

obj[0]  = (int)((byte*)(&MdConstantZeroFreeGlobalAllocAnsi.GetReplyMessageIsolatedStoragePermissionAttribute))[0] ^ 77;
obj[1]  = 24 ^ 67;
obj[2]  = (int)((byte*)(&MdConstantZeroFreeGlobalAllocAnsi.GetReplyMessageIsolatedStoragePermissionAttribute))[2] ^ 181;
obj[3]  = 179 ^ 242;
// ...
obj[20] = 7 ^ 99;

Console.WriteLine(new string(array9));
```

The string consists of 21 characters. Therefore, a 21 byte structure was generated for it.
In IL, it looks like this:
```
.class private explicit ansi sealed MdConstantZeroFreeGlobalAllocAnsi
    extends [System.Runtime]System.ValueType
{
    .pack 1
    .size 21

    .field assembly static initonly valuetype MdConstantZeroFreeGlobalAllocAnsi
        GetReplyMessageIsolatedStoragePermissionAttribute at I_00008B87
}

.data cil I_00008B87 = bytearray (
    47 56 f3 5a 96 56 f9 49 5c d5 51 62 1a e9 b0 0e
    c9 5c 47 25 f2
)
```

The link `at I_00008B87` points to a `.data` block containing 21 bytes.

## Decryptor implementation

A small IL emulator was written to reconstruct the strings. A complete interpreter is not really needed here: it is enough to process the instructions found in the decryptors.

### Candidate search

All of the variants examined began in the same way:
```
ldc.i4    ...
newarr    [System.Runtime]System.Char
```

Using these two instructions, you can find candidates for decryption:
```csharp
if (!instrs[start].IsLdcI4())
    return false;

int length = instrs[start].GetLdcI4Value();

if (length < 0 || length > 100000)
    return false;

if (start + 1 >= instrs.Count || instrs[start + 1].OpCode.Code != Code.Newarr)
    return false;

if (!IsCharType(instrs[start + 1].Operand))
    return false;
```

### Verification of the string type and constructor

Additionally, the type of the `newarr` operand is verified:
```csharp
private static bool IsCharType(object operand)
{
    if (operand is not ITypeDefOrRef tr)
        return false;

    return tr.FullName == "System.Char";
}
```

Similarly, the string constructor is checked:
```csharp
private static bool IsStringCharArrayCtor(object operand)
{
    if (operand is not IMethod m)
        return false;

    if (m.Name != ".ctor")
        return false;

    if (m.DeclaringType?.FullName != "System.String")
        return false;

    var sig = m.MethodSig;

    return sig != null && sig.Params.Count == 1 && sig.Params[0].FullName == "System.Char[]";
}
```

### Emulator value types

4 value types have been introduced to represent the emulator's state:
```csharp
private abstract class Val { }

private sealed class I32 : Val
{
    public readonly int Value;
}

private sealed class Ptr : Val
{
    public readonly byte[] Data;
    public readonly int Offset;
}

private sealed class Chars : Val
{
    public readonly int?[] Data;
}

private sealed class ArgAddr : Val
{
    public readonly int Index;
}
```

`I32` stores an integer value, `Ptr` stores a pointer to an RVA block and an offset within it, `Chars` stores an emulated character array, and `ArgAddr` stores the address of a method argument.
The last type is needed to handle indirect access to arguments via `ldarga`, `ldobj`, and `stobj`.

### Emulator state

The emulator state consists of several parts:
```csharp
var eval = new Stack<Val>();
var locals = new Dictionary<int, Val>();
var args = new Dictionary<int, Val>();
Chars chars = null;
```

`eval` simulates a stack; `locals` stores the values of local variables; `args` stores the values of arguments, which are accessible via indirect addressing.

### The Step method

The main task is performed using the `Step` method, which interprets instructions sequentially.
For example, loading constants and working with the stack:
```csharp
case Code.Ldc_I4:
case Code.Ldc_I4_S:
case Code.Ldc_I4_0:
case Code.Ldc_I4_1:
case Code.Ldc_I4_2:
case Code.Ldc_I4_3:
case Code.Ldc_I4_4:
case Code.Ldc_I4_5:
case Code.Ldc_I4_6:
case Code.Ldc_I4_7:
case Code.Ldc_I4_8:
case Code.Ldc_I4_M1:
    eval.Push(new I32(ins.GetLdcI4Value()));
    return true;

case Code.Dup:
    if (eval.Count == 0)
        return false;

    eval.Push(eval.Peek());
    return true;

case Code.Pop:
    if (eval.Count == 0)
        return false;

    eval.Pop();
    return true;

/// ...
```

### Local variable names

All `ldloc` and `stloc` options are supported for local variables, including the short forms:
```csharp
case Code.Ldloc:
case Code.Ldloc_S:
case Code.Ldloc_0:
case Code.Ldloc_1:
case Code.Ldloc_2:
case Code.Ldloc_3:
{
    var local = ins.GetLocal(method.Body.Variables);

    if (local == null || !locals.TryGetValue(local.Index, out var v))
        return false;

    eval.Push(v);
    return true;
}
```

Writing to a local variable works in a similar way: the value is popped off the stack and stored at the local variable's index.

## Reading an RVA block

### InitialValue from dnlib

Dnlib automatically provides the contents of a field with an RVA via `InitialValue`. Therefore, there is no need to manually parse the PE file and calculate the file offset:

```csharp
case Code.Ldsflda:
    if (ins.Operand is not IField field)
        return false;

    var def = field.ResolveFieldDef();

    if (def == null || !def.HasFieldRVA || def.InitialValue == null)
        return false;

    eval.Push(new Ptr(def.InitialValue, 0));
    return true;
```

### Pointer arithmetic

Next, the emulator handles pointer arithmetic.
For `add` and `sub`, the combinations `Ptr + I32` and `Ptr - I32` are supported. For integer operands, `add`, `sub`, `xor`, `or`, `and`, `mul`, `shl`, `shr`, and `shr.un` are implemented.

### Reading data via LoadInd

Data is read via `LoadInd`:
```csharp
case Code.Ldind_U1:
case Code.Ldind_I1:
case Code.Ldind_U2:
case Code.Ldind_I2:
case Code.Ldind_I4:
    return LoadInd(eval, code);
```

The method checks the pointer type, the array bounds, and the size of the value being read. Depending on the opcode, one, two, or four bytes are retrieved.
For example, for `ldind.u1`:
```csharp
case Code.Ldind_U1:
    v = p.Data[p.Offset];
    break;
```

`BitConverter` is used for `ldind.u2` and `ldind.i2`, and the signed variants additionally account for sign extension.

## Indirect access to arguments

The decryptor also contains instructions for working with argument addresses:
```
ldarga.s
ldobj
stobj
```

They are simulated without actually manipulating memory. With `ldarga`, `ArgAddr` is pushed onto the stack along with the argument index. `ldobj` retrieves the stored value from the `args` dictionary, and `stobj` writes it back.
In this way, the emulator preserves the semantics of the desired operations without creating actual memory addresses.

## Handling branches

There are also useless branches that do not change the actual order of execution:
```
br.s IL_0010
IL_0010:
```

A separate processing step has been added for them:
```csharp
case Code.Br:
case Code.Br_S:
    if (ins.Operand is not Instruction target)
        return false;

    int from = method.Body.Instructions.IndexOf(ins);
    int to = method.Body.Instructions.IndexOf(target);

    return to == from + 1;
```

Only a branch to the next instruction is supported. Any other branch results in the candidate being rejected by the emulator.

## String reconstruction

The block ends with a call to `newobj System.String::.ctor(char[])`.
At this point, the emulator verifies that the expected array is at the top of the stack and that its length matches the original:
```csharp
if (code == Code.Newobj && ip != start)
{
    if (!IsStringCharArrayCtor(ins.Operand))
        return false;

    if (eval.Count == 0 || eval.Peek() is not Chars built)
        return false;

    if (built.Data.Length != length)
        return false;

    var buf = new char[length];

    for (int c = 0; c < length; c++)
    {
        if (built.Data[c] is not int ch)
            return false;

        buf[c] = (char)(ch & 0xFFFF);
    }

    text = new string(buf);
    end = ip;
    return true;
}
```

### The int?[] array and unfilled characters

The array is stored as `int?[]`. This is done intentionally: `null` means that the corresponding element has not been written.
If even one character remains unfilled, the candidate is rejected entirely.

## Replacing the decryptor

### Replacing the instruction range with ldstr

After successful emulation, the entire range of instructions from `ldc.i4` to the constructor call is removed and replaced with a single `ldstr`:

```csharp
for (int k = end; k >= i; k--)
    instrs.RemoveAt(k);

instrs.Insert(i, Instruction.Create(OpCodes.Ldstr, text));
count++;
```

### Result

Voila, the string has been decrypted:
```csharp
Console.WriteLine("\n[FAIL] Access denied");
```

## Conclusion

I couldn't come up with anything.

## Decryptor src

```csharp
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ArmShprot;

internal static class StringDecryptor
{
    public static int Process(ModuleDef module)
    {
        int count = 0;

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody)
                    continue;

                count += ProcessMethod(method);
            }
        }

        return count;
    }

    private static int ProcessMethod(MethodDef method)
    {
        var body = method.Body;
        var instrs = body.Instructions;
        int count = 0;

        for (int i = 0; i < instrs.Count - 1; i++)
        {
            if (!TryDecrypt(method, i, out int end, out string text))
                continue;

            for (int k = end; k >= i; k--)
                instrs.RemoveAt(k);

            instrs.Insert(i, Instruction.Create(OpCodes.Ldstr, text));
            count++;
        }

        if (count > 0)
        {
            body.SimplifyBranches();
            body.OptimizeBranches();
        }

        return count;
    }

    private static bool TryDecrypt(MethodDef method, int start, out int end, out string text)
    {
        end = -1;
        text = null;

        var instrs = method.Body.Instructions;

        if (!instrs[start].IsLdcI4())
            return false;

        int length = instrs[start].GetLdcI4Value();

        if (length < 0 || length > 100000)
            return false;

        if (start + 1 >= instrs.Count || instrs[start + 1].OpCode.Code != Code.Newarr)
            return false;

        if (!IsCharType(instrs[start + 1].Operand))
            return false;

        var eval = new Stack<Val>();
        var locals = new Dictionary<int, Val>();
        var args = new Dictionary<int, Val>();
        Chars chars = null;

        int limit = Math.Min(instrs.Count, start + 16 + length * 20);

        for (int ip = start; ip < limit; ip++)
        {
            var ins = instrs[ip];
            var code = ins.OpCode.Code;

            if (code == Code.Newobj && ip != start)
            {
                if (!IsStringCharArrayCtor(ins.Operand))
                    return false;

                if (eval.Count == 0 || eval.Peek() is not Chars built)
                    return false;

                if (built.Data.Length != length)
                    return false;

                var buf = new char[length];

                for (int c = 0; c < length; c++)
                {
                    if (built.Data[c] is not int ch)
                        return false;

                    buf[c] = (char)(ch & 0xFFFF);
                }

                text = new string(buf);
                end = ip;
                return true;
            }

            if (!Step(method, ins, eval, locals, args, ref chars))
                return false;
        }

        return false;
    }

    private static bool Step(MethodDef method, Instruction ins, Stack<Val> eval, Dictionary<int, Val> locals, Dictionary<int, Val> args, ref Chars chars)
    {
        var code = ins.OpCode.Code;

        switch (code)
        {
            case Code.Nop:
                return true;

            case Code.Ldc_I4:
            case Code.Ldc_I4_S:
            case Code.Ldc_I4_0:
            case Code.Ldc_I4_1:
            case Code.Ldc_I4_2:
            case Code.Ldc_I4_3:
            case Code.Ldc_I4_4:
            case Code.Ldc_I4_5:
            case Code.Ldc_I4_6:
            case Code.Ldc_I4_7:
            case Code.Ldc_I4_8:
            case Code.Ldc_I4_M1:
                eval.Push(new I32(ins.GetLdcI4Value()));
                return true;

            case Code.Dup:
                if (eval.Count == 0)
                    return false;

                eval.Push(eval.Peek());
                return true;

            case Code.Pop:
                if (eval.Count == 0)
                    return false;

                eval.Pop();
                return true;

            case Code.Newarr:
                if (!IsCharType(ins.Operand))
                    return false;

                if (eval.Count == 0 || eval.Pop() is not I32 len || len.Value < 0 || len.Value > 100000)
                    return false;

                chars = new Chars(new int?[len.Value]);
                eval.Push(chars);
                return true;

            case Code.Ldloc:
            case Code.Ldloc_S:
            case Code.Ldloc_0:
            case Code.Ldloc_1:
            case Code.Ldloc_2:
            case Code.Ldloc_3:
                {
                    var local = ins.GetLocal(method.Body.Variables);

                    if (local == null || !locals.TryGetValue(local.Index, out var v))
                        return false;

                    eval.Push(v);
                    return true;
                }

            case Code.Stloc:
            case Code.Stloc_S:
            case Code.Stloc_0:
            case Code.Stloc_1:
            case Code.Stloc_2:
            case Code.Stloc_3:
                {
                    var local = ins.GetLocal(method.Body.Variables);

                    if (local == null || eval.Count == 0)
                        return false;

                    locals[local.Index] = eval.Pop();
                    return true;
                }

            case Code.Ldsflda:
                if (ins.Operand is not IField field)
                    return false;

                var def = field.ResolveFieldDef();

                if (def == null || !def.HasFieldRVA || def.InitialValue == null)
                    return false;

                eval.Push(new Ptr(def.InitialValue, 0));
                return true;

            case Code.Conv_I:
            case Code.Conv_U:
            case Code.Conv_I4:
            case Code.Conv_U4:
                return true;

            case Code.Add:
            case Code.Sub:
            case Code.Xor:
            case Code.Or:
            case Code.And:
            case Code.Mul:
            case Code.Shl:
            case Code.Shr:
            case Code.Shr_Un:
                return Bin(eval, code);

            case Code.Ldind_U1:
            case Code.Ldind_I1:
            case Code.Ldind_U2:
            case Code.Ldind_I2:
            case Code.Ldind_I4:
                return LoadInd(eval, code);

            case Code.Stelem_I2:
            case Code.Stelem_I:
                return StoreChar(eval);

            case Code.Ldarg:
            case Code.Ldarg_S:
            case Code.Ldarg_0:
            case Code.Ldarg_1:
            case Code.Ldarg_2:
            case Code.Ldarg_3:
            case Code.Ldarga:
            case Code.Ldarga_S:
                {
                    int idx = ins.GetParameterIndex();

                    if (idx < 0)
                        return false;

                    eval.Push(new ArgAddr(idx));
                    return true;
                }

            case Code.Ldobj:
                if (eval.Count == 0 || eval.Pop() is not ArgAddr addr)
                    return false;

                if (!args.TryGetValue(addr.Index, out var held))
                    return false;

                eval.Push(held);
                return true;

            case Code.Stobj:
                if (eval.Count < 2)
                    return false;

                var stored = eval.Pop();

                if (eval.Pop() is not ArgAddr storedAddr)
                    return false;

                args[storedAddr.Index] = stored;
                return true;

            case Code.Br:
            case Code.Br_S:
                if (ins.Operand is not Instruction target)
                    return false;

                int from = method.Body.Instructions.IndexOf(ins);
                int to = method.Body.Instructions.IndexOf(target);

                return to == from + 1;

            default:
                return false;
        }
    }

    private static bool Bin(Stack<Val> eval, Code code)
    {
        if (eval.Count < 2)
            return false;

        var b = eval.Pop();
        var a = eval.Pop();

        if (a is Ptr p && b is I32 off && (code == Code.Add || code == Code.Sub))
        {
            int delta = code == Code.Add ? off.Value : -off.Value;
            eval.Push(new Ptr(p.Data, p.Offset + delta));
            return true;
        }

        if (a is I32 ia && b is I32 ib)
        {
            int r;

            switch (code)
            {
                case Code.Add:
                    r = ia.Value + ib.Value;
                    break;
                case Code.Sub:
                    r = ia.Value - ib.Value;
                    break;
                case Code.Xor:
                    r = ia.Value ^ ib.Value;
                    break;
                case Code.Or:
                    r = ia.Value | ib.Value;
                    break;
                case Code.And:
                    r = ia.Value & ib.Value;
                    break;
                case Code.Mul:
                    r = ia.Value * ib.Value;
                    break;
                case Code.Shl:
                    r = ia.Value << ib.Value;
                    break;
                case Code.Shr:
                    r = ia.Value >> ib.Value;
                    break;
                case Code.Shr_Un:
                    r = (int)((uint)ia.Value >> ib.Value);
                    break;
                default:
                    r = 0;
                    break;
            }

            eval.Push(new I32(r));
            return true;
        }

        return false;
    }

    private static bool LoadInd(Stack<Val> eval, Code code)
    {
        if (eval.Count == 0 || eval.Pop() is not Ptr p)
            return false;

        if (p.Data == null || p.Offset < 0)
            return false;

        int size;

        if (code is Code.Ldind_U1 or Code.Ldind_I1)
            size = 1;
        else if (code is Code.Ldind_U2 or Code.Ldind_I2)
            size = 2;
        else
            size = 4;

        if (p.Offset + size > p.Data.Length)
            return false;

        int v;

        switch (code)
        {
            case Code.Ldind_U1:
                v = p.Data[p.Offset];
                break;
            case Code.Ldind_I1:
                v = (sbyte)p.Data[p.Offset];
                break;
            case Code.Ldind_U2:
                v = BitConverter.ToUInt16(p.Data, p.Offset);
                break;
            case Code.Ldind_I2:
                v = BitConverter.ToInt16(p.Data, p.Offset);
                break;
            default:
                v = BitConverter.ToInt32(p.Data, p.Offset);
                break;
        }

        eval.Push(new I32(v));
        return true;
    }

    private static bool StoreChar(Stack<Val> eval)
    {
        if (eval.Count < 3)
            return false;

        if (eval.Pop() is not I32 val)
            return false;

        if (eval.Pop() is not I32 idx)
            return false;

        if (eval.Pop() is not Chars arr)
            return false;

        if (idx.Value < 0 || idx.Value >= arr.Data.Length)
            return false;

        arr.Data[idx.Value] = val.Value;
        return true;
    }

    private static bool IsCharType(object operand)
    {
        if (operand is not ITypeDefOrRef tr)
            return false;

        return tr.FullName == "System.Char";
    }

    private static bool IsStringCharArrayCtor(object operand)
    {
        if (operand is not IMethod m)
            return false;

        if (m.Name != ".ctor")
            return false;

        if (m.DeclaringType?.FullName != "System.String")
            return false;

        var sig = m.MethodSig;

        return sig != null && sig.Params.Count == 1 && sig.Params[0].FullName == "System.Char[]";
    }

    private abstract class Val { }

    private sealed class I32 : Val
    {
        public readonly int Value;

        public I32(int value)
        {
            Value = value;
        }
    }

    private sealed class Ptr : Val
    {
        public readonly byte[] Data;
        public readonly int Offset;

        public Ptr(byte[] data, int offset)
        {
            Data = data;
            Offset = offset;
        }
    }

    private sealed class Chars : Val
    {
        public readonly int?[] Data;

        public Chars(int?[] data)
        {
            Data = data;
        }
    }

    private sealed class ArgAddr : Val
    {
        public readonly int Index;

        public ArgAddr(int index)
        {
            Index = index;
        }
    }
}
```
