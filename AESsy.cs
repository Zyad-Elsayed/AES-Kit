using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string mode = null, keyHex = null, ivHex = null, inputText = null, inputFile = null,
               outputFile = null, outputFormat = "base64", keySize = "256", password = null, saltPassword = null, saltHex = null;
        bool outputToConsole = false, saveKeyIV = false, logErrors = false, isPasswordDerived = false;

        if (args.Length == 1 && args[0].ToLower() == "-help")
        {
            ShowHelp();
            return;
        }

        //  arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-encrypt": mode = "E"; break;
                case "-decrypt": mode = "D"; break;
                case "-key": if (i + 1 < args.Length) keyHex = args[++i]; break;
                case "-iv": if (i + 1 < args.Length) ivHex = args[++i]; break;
                case "-in": if (i + 1 < args.Length) inputFile = args[++i]; break;
                case "-out": if (i + 1 < args.Length) outputFile = args[++i]; break;
                case "-text": if (i + 1 < args.Length) inputText = args[++i]; break;
                case "-console": outputToConsole = true; break;
                case "-savekeyiv": saveKeyIV = true; break;
                case "-format": if (i + 1 < args.Length) outputFormat = args[++i].ToLower(); break;
                case "-keysize": if (i + 1 < args.Length) keySize = args[++i]; break;
                case "-password": if (i + 1 < args.Length) password = args[++i]; break;
                case "-salt": if (i + 1 < args.Length) saltPassword = args[++i]; break;
                case "-log": logErrors = true; break;
            }
        }

        try
        {
            byte[] key = null, iv = null;

            // interactive mode
            if (mode == null)
            {
                mode = GetInteractiveInput("Enter mode (E = Encrypt, D = Decrypt): ", s => s.Trim().ToUpper(), "E");
                keySize = GetInteractiveInput("Enter key size (128/192/256): ", s => s.Trim(), "256");

                if (mode == "E")
                {
                    outputFormat = GetInteractiveInput("Output format (base64/hex): ", s => s.Trim().ToLower(), "base64");
                    saveKeyIV = GetInteractiveBool("Save key/IV to file? (y/n): ", s => s.Trim().ToLower() == "y", false);

                    // Ask if user has key/IV or wants to use password
                    if (GetInteractiveBool("Do you have a key and IV? (y/n): ", s => s.Trim().ToLower() == "y", false))
                    {
                        keyHex = GetInteractiveInput("Enter key (hex): ", s => s.Trim(), "");
                        ivHex = GetInteractiveInput("Enter IV (hex): ", s => s.Trim(), "");
                        if (string.IsNullOrEmpty(keyHex) || string.IsNullOrEmpty(ivHex))
                        {
                            Console.WriteLine("Key and IV are required if using existing values. Generating new ones...");
                            GenerateKeyIV(int.Parse(keySize), out key, out iv);
                            keyHex = ByteArrayToHexString(key);
                            ivHex = ByteArrayToHexString(iv);
                            Console.WriteLine($"Generated Key: {keyHex}");
                            Console.WriteLine($"Generated IV:  {ivHex}");
                        }
                    }
                    else
                    {
                        if (GetInteractiveBool("Do you want to use a password instead of key/IV? (y/n): ", s => s.Trim().ToLower() == "y", false))
                        {
                            password = GetInteractiveInput("Enter password: ", s => s.Trim(), "");
                            if (string.IsNullOrEmpty(password))
                            {
                                throw new ArgumentException("Password cannot be empty.");
                            }
                            saltPassword = GetInteractiveInput("Enter used salt password: ", s => s.Trim(), "");
                            byte[] salt = DeriveSaltFromPassword(saltPassword);
                            saltHex = ByteArrayToHexString(salt);
                            DeriveKeyFromPassword(password, int.Parse(keySize), salt, out key, out iv);
                            keyHex = ByteArrayToHexString(key);
                            ivHex = ByteArrayToHexString(iv);
                            isPasswordDerived = true;
                            Console.WriteLine($"Generated Salt (from salt password): {saltHex}");
                            Console.WriteLine($"Derived Key: {keyHex}");
                            Console.WriteLine($"Derived IV:  {ivHex}");
                        }
                        else
                        {
                            GenerateKeyIV(int.Parse(keySize), out key, out iv);
                            keyHex = ByteArrayToHexString(key);
                            ivHex = ByteArrayToHexString(iv);
                            Console.WriteLine($"Generated Key: {keyHex}");
                            Console.WriteLine($"Generated IV:  {ivHex}");
                        }
                    }
                }
                else if (mode == "D")
                {
                    //  decryption
                    if (GetInteractiveBool("Do you want to use a password instead of key/IV? (y/n): ", s => s.Trim().ToLower() == "y", false))
                    {
                        password = GetInteractiveInput("Enter password: ", s => s.Trim(), "");
                        if (string.IsNullOrEmpty(password))
                        {
                            throw new ArgumentException("Password cannot be empty.");
                        }
                        saltPassword = GetInteractiveInput("Enter used salt password: ", s => s.Trim(), "");
                        if (string.IsNullOrEmpty(saltPassword))
                        {
                            throw new ArgumentException("Salt password is required for password-based decryption.");
                        }
                        byte[] salt = DeriveSaltFromPassword(saltPassword);
                        saltHex = ByteArrayToHexString(salt);
                        DeriveKeyFromPassword(password, int.Parse(keySize), salt, out key, out iv);
                        keyHex = ByteArrayToHexString(key);
                        ivHex = ByteArrayToHexString(iv);
                        isPasswordDerived = true;
                        Console.WriteLine($"Derived Salt (from salt password): {saltHex}");
                        Console.WriteLine($"Derived Key: {keyHex}");
                        Console.WriteLine($"Derived IV:  {ivHex}");
                    }
                    else
                    {
                        keyHex = GetInteractiveInput("Enter key (hex): ", s => s.Trim(), "");
                        ivHex = GetInteractiveInput("Enter IV (hex): ", s => s.Trim(), "");
                        if (string.IsNullOrEmpty(keyHex) || string.IsNullOrEmpty(ivHex))
                        {
                            throw new ArgumentException("Key and IV are required for decryption.");
                        }
                    }
                }
            }
            else if (password != null)
            {
                // hadlenig password-based key derivation for commandline mode
                if (string.IsNullOrEmpty(saltPassword))
                {
                    throw new ArgumentException("Salt password is required when using a password.");
                }
                byte[] salt = DeriveSaltFromPassword(saltPassword);
                saltHex = ByteArrayToHexString(salt);
                DeriveKeyFromPassword(password, int.Parse(keySize), salt, out key, out iv);
                keyHex = ByteArrayToHexString(key);
                ivHex = ByteArrayToHexString(iv);
                isPasswordDerived = true;
                if (mode == "E")
                {
                    Console.WriteLine($"Generated Salt (from salt password): {saltHex}");
                    Console.WriteLine($"Derived Key: {keyHex}");
                    Console.WriteLine($"Derived IV:  {ivHex}");
                }
                else
                {
                    Console.WriteLine($"Derived Salt (from salt password): {saltHex}");
                    Console.WriteLine($"Derived Key: {keyHex}");
                    Console.WriteLine($"Derived IV:  {ivHex}");
                }
            }

            // Key/IV handling
            int keySizeBits = int.Parse(keySize);
            if (mode == "E")
            {
                 // throw the exception if key/IV are explicitly provided (not derived from password)
                if (!isPasswordDerived && password != null && (keyHex != null || ivHex != null))
                    throw new ArgumentException("Cannot use both password and explicit key/IV");

                if (!isPasswordDerived && (keyHex == null || ivHex == null))
                {
                    GenerateKeyIV(keySizeBits, out key, out iv);
                    keyHex = ByteArrayToHexString(key);
                    ivHex = ByteArrayToHexString(iv);
                    Console.WriteLine($"Generated Key: {keyHex}");
                    Console.WriteLine($"Generated IV:  {ivHex}");
                }
                else if (!isPasswordDerived)
                {
                    key = HexStringToByteArray(keyHex);
                    iv = HexStringToByteArray(ivHex);
                }
            }
            else // decrypt
            {
                if (password != null)
                {
                    if (saltPassword == null)
                        throw new ArgumentException("Salt password is required for password-based decryption.");
                   
                }
                else if (keyHex == null || ivHex == null)
                {
                    throw new ArgumentException("Key and IV or password with salt required for decryption");
                }
                else
                {
                    key = HexStringToByteArray(keyHex);
                    iv = HexStringToByteArray(ivHex);
                }
            }

           //  lengths validation 
            ValidateKeyIV(key, iv, keySizeBits);

            // save Key/IV and Salt if requested
            if (saveKeyIV)
                SaveKeyIVToFile(keyHex, ivHex, keySize, saltHex);

            // Get input
            if (inputFile != null)
                inputText = File.ReadAllText(inputFile);
            else if (inputText == null)
                inputText = GetInteractiveInput(mode == "E" ? "Enter plaintext: " : "Enter encrypted text: ", s => s, "");

            // main
            string outputText;
            if (mode == "E")
            {
                outputText = EncryptAES(inputText, key, iv, outputFormat);
                Console.WriteLine($"Encrypted ({outputFormat}): {outputText}");
            }
            else
            {
                outputText = DecryptAES(inputText, key, iv);
                Console.WriteLine($"Decrypted: {outputText}");
            }

            // handling o/p
            if (outputFile != null)
                File.WriteAllText(outputFile, outputText);
            if (outputToConsole || outputFile == null)
                Console.WriteLine($"\nFinal Output:\n{outputText}");
        }
        catch (Exception ex)
        {
            HandleError(ex, logErrors);
        }
    }

    static string GetInteractiveInput(string prompt, Func<string, string> transform, string defaultValue)
    {
        Console.Write(prompt);
        string input = Console.ReadLine();
        return string.IsNullOrEmpty(input) ? defaultValue : transform(input);
    }

    static bool GetInteractiveBool(string prompt, Func<string, bool> transform, bool defaultValue)
    {
        Console.Write(prompt);
        string input = Console.ReadLine();
        return string.IsNullOrEmpty(input) ? defaultValue : transform(input);
    }

    static void GenerateKeyIV(int keySizeBits, out byte[] key, out byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = keySizeBits;
            aes.GenerateKey();
            aes.GenerateIV();
            key = aes.Key;
            iv = aes.IV;
        }
    }

    static byte[] DeriveSaltFromPassword(string saltPassword)
    {
        if (string.IsNullOrEmpty(saltPassword))
            saltPassword = "default"; // Fallback to a default value if empty
        using (var sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltPassword));
            // using 16 bytes for salt
            byte[] salt = new byte[16];
            Array.Copy(hash, salt, 16);
            return salt;
        }
    }

    static void DeriveKeyFromPassword(string password, int keySizeBits, byte[] salt, out byte[] key, out byte[] iv)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
        {
            key = pbkdf2.GetBytes(keySizeBits / 8);
            iv = pbkdf2.GetBytes(16); 
        }
    }

    static void SaveKeyIVToFile(string keyHex, string ivHex, string keySize, string saltHex)
    {
        File.WriteAllText("key_iv.txt", $"Key: {keyHex}\nIV: {ivHex}\nKeySize: {keySize}\nSalt: {saltHex}");
        Console.WriteLine("Key, IV, and Salt saved to key_iv.txt");
    }

    static void ValidateKeyIV(byte[] key, byte[] iv, int keySizeBits)
    {
        int keySizeBytes = keySizeBits / 8;
        if (key.Length != keySizeBytes)
            throw new ArgumentException($"Key must be {keySizeBytes} bytes for {keySizeBits}-bit encryption");
        if (iv.Length != 16)
            throw new ArgumentException("IV must be 16 bytes");
    }

    static string EncryptAES(string plaintext, byte[] key, byte[] iv, string format)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                cs.FlushFinalBlock();
                byte[] encrypted = ms.ToArray();
                return format == "hex" ? ByteArrayToHexString(encrypted) : Convert.ToBase64String(encrypted);
            }
        }
    }

    static string DecryptAES(string encrypted, byte[] key, byte[] iv)
    {
        byte[] encryptedBytes;
        try
        {
            encryptedBytes = Convert.FromBase64String(encrypted);
        }
        catch
        {
            try
            {
                encryptedBytes = HexStringToByteArray(encrypted);
            }
            catch
            {
                throw new ArgumentException("Input must be Base64 or Hex encoded");
            }
        }

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(encryptedBytes))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var msPlain = new MemoryStream())
            {
                cs.CopyTo(msPlain);
                return Encoding.UTF8.GetString(msPlain.ToArray());
            }
        }
    }

    static void HandleError(Exception ex, bool logErrors)
    {
        string errorMessage = $"Error: {ex.Message}";
        Console.WriteLine(errorMessage);
        if (logErrors)
            File.AppendAllText("error_log.txt", $"{DateTime.Now}: {errorMessage}\n");
    }

    static string ByteArrayToHexString(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "").ToLower();
    static byte[] HexStringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0) throw new ArgumentException("Invalid hex string length");
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    static void ShowHelp()
    {
        Console.WriteLine("Usage: ConsoleApp.exe [options]");
        Console.WriteLine("Options:");
        Console.WriteLine("  -encrypt         Encrypt mode");
        Console.WriteLine("  -decrypt         Decrypt mode");
        Console.WriteLine("  -key <hex>       AES key in hex");
        Console.WriteLine("  -iv <hex>        AES IV in hex");
        Console.WriteLine("  -password <pwd>  Derive key/IV from password");
        Console.WriteLine("  -keysize <size>  Key size (128/192/256, default: 256)");
        Console.WriteLine("  -salt <str>      Salt password (or any string) for password derivation");
        Console.WriteLine("  -in <file>       Input file");
        Console.WriteLine("  -out <file>      Output file");
        Console.WriteLine("  -text <string>   Input text");
        Console.WriteLine("  -format <type>   Output format (base64/hex, default: base64)");
        Console.WriteLine("  -console         Print to console");
        Console.WriteLine("  -savekeyiv       Save generated key/IV to file");
        Console.WriteLine("  -log             Log errors to file");
        Console.WriteLine("  -help            Show this help");
    }
}
