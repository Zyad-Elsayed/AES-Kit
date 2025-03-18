using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();

            
            string output =
                "byte[] key = new byte[16] { 0x" + BitConverter.ToString(aes.Key).Replace("-", ", 0x") + " };\n" +
                "byte[] iv = new byte[16] { 0x" + BitConverter.ToString(aes.IV).Replace("-", ", 0x") + " };\n\n" +
                "Key: " + BitConverter.ToString(aes.Key).Replace("-", "").ToLower() + "\n" +
                "IV: " + BitConverter.ToString(aes.IV).Replace("-", "").ToLower();

            
            Console.WriteLine(output);

            
            string filePath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            File.WriteAllText(filePath, output);

            Console.WriteLine($"\nOutput saved to: {filePath}");
            Console.WriteLine("\nCopy the output, then press Enter to exit...");
            Console.ReadLine();
        }
    }
}
