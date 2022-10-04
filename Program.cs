using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

// plain-text
Console.WriteLine("== password ==");
string passwordStr = "test";
byte[] passwordBytes = Encoding.ASCII.GetBytes(passwordStr);

Console.WriteLine($"Bytes: {ToHex(passwordBytes)}");
Console.WriteLine($"Testo: {ToEscapedStr(passwordStr)}");
Console.WriteLine();


// hash
Console.WriteLine("== SHA512(password) ==");
byte[] hashBytes = SHA512.HashData(passwordBytes);
string hashStr = Encoding.ASCII.GetString(hashBytes);

Console.WriteLine($"Bytes: {ToHex(hashBytes)}");
Console.WriteLine($"Testo: {ToEscapedStr(hashStr)}");
Console.WriteLine();


// sale
Console.WriteLine("== sale ==");
string saltStr = "sAlT_s3cr3T!$";
byte[] saltBytes = Encoding.ASCII.GetBytes(saltStr);

Console.WriteLine($"Bytes: {ToHex(saltBytes)}");
Console.WriteLine($"Testo: {ToEscapedStr(saltStr)}");
Console.WriteLine();


// hash + sale
Console.WriteLine("== HMACSHA512(sale, password) ==");
byte[] saltedHashBytes = HMACSHA512.HashData(saltBytes, passwordBytes);
string saltedHashStr = Encoding.ASCII.GetString(saltedHashBytes);

Console.WriteLine($"Bytes: {ToHex(saltedHashBytes)}");
Console.WriteLine($"Testo: {ToEscapedStr(saltedHashStr)}");
Console.WriteLine();


// hash + sale + key-derivation
Console.WriteLine("== HMACSHA512PBKDF2(password, sale) ==");
byte[] keyDerivationSaltedHashBytes = KeyDerivation.Pbkdf2(passwordStr, saltBytes, KeyDerivationPrf.HMACSHA512, 10000000, 32);
string keyDerivationSaltedHashStr = Encoding.ASCII.GetString(keyDerivationSaltedHashBytes);

Console.WriteLine($"Bytes: {ToHex(keyDerivationSaltedHashBytes)}");
Console.WriteLine($"Testo: {ToEscapedStr(keyDerivationSaltedHashStr)}");
Console.WriteLine();


// converte array di byte in stringa esadecimale
string ToHex(byte[] bytes)
{
    IEnumerable<string> hexBytes = Convert.ToHexString(bytes).Chunk(2).Select(x => string.Join("", x));
    return string.Join(" ", hexBytes);
}

// converte stringa di testo in stringa in formato C#
string ToEscapedStr(string str)
{
    char[] array = str.ToCharArray();
    StringBuilder stringBuilder = new StringBuilder(str.Length * 10);
    for (int i = 0; i < array.Length; i++)
    {
        char c = array[i];
        switch (c)
        {
            case '\0':
                stringBuilder.Append("\\0");
                continue;
            case '\a':
                stringBuilder.Append("\\a");
                continue;
            case '\b':
                stringBuilder.Append("\\b");
                continue;
            case '\f':
                stringBuilder.Append("\\f");
                continue;
            case '\n':
                stringBuilder.Append("\\n");
                continue;
            case '\r':
                stringBuilder.Append("\\r");
                continue;
            case '\t':
                stringBuilder.Append("\\t");
                continue;
            case '\v':
                stringBuilder.Append("\\v");
                continue;
            case '\'':
                stringBuilder.Append("\\'");
                continue;
            case '"':
                stringBuilder.Append("\\\"");
                continue;
            case '\\':
                stringBuilder.Append("\\\\");
                continue;
        }
        if (c >= ' ' && c <= '~')
        {
            stringBuilder.Append(c);
            continue;
        }
        string text = ((ulong)c).ToString("X");
        if (text.Length < 4)
        {
            char? c2 = ((i == array.Length - 1) ? null : new char?(array[i + 1]));
            if ((!(c2 >= '0') || !(c2 <= '9')) && (!(c2 >= 'a') || !(c2 <= 'f')) && (!(c2 >= 'A') || !(c2 <= 'F')))
            {
                stringBuilder.AppendFormat("\\x{0}", text);
            }
            else
            {
                stringBuilder.AppendFormat("\\u{0:4:0}", text);
            }
        }
        else if (text.Length == 4)
        {
            stringBuilder.AppendFormat("\\u{0}", text);
        }
        else
        {
            stringBuilder.AppendFormat("\\U{0:8:0}", text);
        }
    }
    return $"\"{stringBuilder}\"";
}
