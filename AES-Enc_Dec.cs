using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string mode = null, keyHex = null, ivHex = null, inputText = null, inputFile = null, outputFile = null;
        bool outputToConsole = false;

        // Display help menu if -help is provided
        if (args.Length == 1 && args[0].ToLower() == "-help")
        {
            ShowHelp();
            return;
        }

        // Parse command-line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-encrypt":
                    mode = "E";
                    break;
                case "-decrypt":
                    mode = "D";
                    break;
                case "-key":
                    if (i + 1 < args.Length) keyHex = args[++i];
                    break;
                case "-iv":
                    if (i + 1 < args.Length) ivHex = args[++i];
                    break;
                case "-in":
                    if (i + 1 < args.Length) inputFile = args[++i];
                    break;
                case "-out":
                    if (i + 1 < args.Length) outputFile = args[++i];
                    break;
                case "-text":
                    if (i + 1 < args.Length) inputText = args[++i];
                    break;
                case "-console":
                    outputToConsole = true;
                    break;
                default:
                    Console.WriteLine($"Unknown argument: {args[i]}");
                    ShowHelp();
                    return;
            }
        }

        // If no mode was provided, fall back to interactive mode
        if (mode == null)
        {
            Console.Write("Enter mode (E = Encrypt, D = Decrypt): ");
            mode = Console.ReadLine()?.Trim().ToUpper();
        }

        // Read or generate key and IV
        byte[] key, iv;
        if (mode == "E") // Encryption mode - generate key/IV if not provided
        {
            if (keyHex == null || ivHex == null)
            {
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    key = aes.Key;
                    iv = aes.IV;

                    // Convert to hex strings
                    keyHex = ByteArrayToHexString(key);
                    ivHex = ByteArrayToHexString(iv);
                }
                Console.WriteLine($"Generated Key: {keyHex}");
                Console.WriteLine($"Generated IV:  {ivHex}");
            }
            else
            {
                key = HexStringToByteArray(keyHex);
                iv = HexStringToByteArray(ivHex);
            }
        }
        else // Decryption mode - key and IV are required
        {
            if (keyHex == null || ivHex == null)
            {
                Console.WriteLine("Error: Key and IV are required for decryption.");
                return;
            }
            key = HexStringToByteArray(keyHex);
            iv = HexStringToByteArray(ivHex);
        }

        // Validate key and IV lengths
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
        {
            Console.WriteLine("Invalid key length! Use 16, 24, or 32 bytes.");
            return;
        }
        if (iv.Length != 16)
        {
            Console.WriteLine("Invalid IV length! IV must be 16 bytes.");
            return;
        }

        // Read input from file or direct text
        if (inputFile != null)
        {
            try
            {
                inputText = File.ReadAllText(inputFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file {inputFile}: {ex.Message}");
                return;
            }
        }
        else if (inputText == null)
        {
            Console.Write(mode == "E" ? "Enter plaintext: " : "Enter encrypted text (Base64): ");
            inputText = Console.ReadLine();
        }

        // Encrypt or Decrypt
        string outputText;
        if (mode == "E")
        {
            outputText = EncryptAES(inputText, key, iv);
            Console.WriteLine($"Encrypted (Base64): {outputText}");
        }
        else if (mode == "D")
        {
            outputText = DecryptAES(inputText, key, iv);
            Console.WriteLine($"Decrypted: {outputText}");
        }
        else
        {
            Console.WriteLine("Invalid mode selected.");
            return;
        }

        // Save output to file or console
        if (outputFile != null)
        {
            try
            {
                File.WriteAllText(outputFile, outputText);
                Console.WriteLine($"Output saved to {outputFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing to file {outputFile}: {ex.Message}");
            }
        }

        if (outputToConsole || outputFile == null)
        {
            Console.WriteLine($"\nFinal Output:\n{outputText}");
        }
    }

    static void ShowHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  ConsoleApp.exe -encrypt|-decrypt [-key <hex>] [-iv <hex>] [-in <file> | -text <string>] [-out <file>] [-console]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -encrypt         Encrypt the input text. If no key/IV provided, they are generated.");
        Console.WriteLine("  -decrypt         Decrypt the input text (requires key and IV).");
        Console.WriteLine("  -key <hex>       AES key in hexadecimal (16, 24, or 32 bytes).");
        Console.WriteLine("  -iv <hex>        AES IV in hexadecimal (16 bytes).");
        Console.WriteLine("  -in <file>       Read input from a file.");
        Console.WriteLine("  -text <string>   Provide input text directly.");
        Console.WriteLine("  -out <file>      Save output to a file.");
        Console.WriteLine("  -console         Print output to the terminal.");
        Console.WriteLine("  -help            Show this help menu.");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  Encrypt a string and auto-generate key/IV:");
        Console.WriteLine("    ConsoleApp.exe -encrypt -text \"Hello World\" -console");
        Console.WriteLine();
        Console.WriteLine("  Encrypt a file with a custom key:");
        Console.WriteLine("    ConsoleApp.exe -encrypt -key c5cdb5... -iv 2684b2... -in plaintext.txt -out encrypted.txt");
        Console.WriteLine();
        Console.WriteLine("  Decrypt a file and print to terminal:");
        Console.WriteLine("    ConsoleApp.exe -decrypt -key c5cdb5... -iv 2684b2... -in encrypted.txt -console");
    }

    static string EncryptAES(string plaintext, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                csEncrypt.FlushFinalBlock();
                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    static string DecryptAES(string encryptedBase64, byte[] key, byte[] iv)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (MemoryStream msPlain = new MemoryStream())
            {
                csDecrypt.CopyTo(msPlain);
                return Encoding.UTF8.GetString(msPlain.ToArray());
            }
        }
    }

    static string ByteArrayToHexString(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "").ToLower();

    static byte[] HexStringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0) throw new ArgumentException("Invalid hex string length.");
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }
}
