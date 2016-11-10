using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Configuration;
using System.Collections.Specialized;
using System.Data.Common;

namespace CryptoAPI
{
    public static class CryptoRAS128Const 
    {
        public const int PROVIDER_RSA_FULL = 1;
        public const int KEY_SIZE = 1024;
        public const string CONTAINER_NAME = "SpiderContainer";
        public const string PROVIDER_NAME = "Microsoft Strong Cryptographic Provider";
        public const string CON_STR_USER_NAME = "Username";
        public const string CON_STR_PASSWORD = "Password";                      
    }
      
    class CryptoRAS128Helper
    {
        public RSACryptoServiceProvider rsa {get; set;}

        public string ConnectionStringParamName { get; set;}
        public string ConnectionString { get; set; }

        public Boolean isSecure { get; set; }
        public string isSecureParamName { get; set; }

        public string Login { get; set; }
        public string LoginParamName { get; set; }

        public string Password { get; set; }
        public string PasswordParamName { get; set; }       
        
        public string publicKey {get; set; }
        public string privateKey { get; set; }
        public string CryptStr(string AStr)
        {
            byte[] lBytes = Encoding.ASCII.GetBytes(AStr);
            byte[] lCryptedBytes = rsa.Encrypt(lBytes, false);
            return GetString(lCryptedBytes);             
        }
        public string DeCryptStr(string AStr)
        {
            byte[] lBytes = GetBytes(AStr);
            byte[] lCryptedBytes = rsa.Decrypt(lBytes, false);
            return Encoding.ASCII.GetString(lCryptedBytes);             
        }

        static byte[] GetBytes(string AStr)
        {
            return Convert.FromBase64String(AStr);           
        }

        static string GetString(byte[] ABytes)
        {
            return Convert.ToBase64String(ABytes);        
        }
        static byte[] GetBytes(string AStr, char ASeparator)
        {
            return Array.ConvertAll(AStr.Split(ASeparator), s => byte.Parse(s));  
        }

        static string GetString(byte[] ABytes, string ASeparator)
        {
            return string.Join(ASeparator, ABytes);
        }
        public void PrintParamsInToConsole()
        {
            Console.Write("ConnectionName {0} ", ConnectionStringParamName);
            Console.Write("isSecureName {0} ", isSecureParamName);
            Console.Write("ConnectioString {0} ", ConnectionString);
            Console.Write("isSecure {0} ", Convert.ToString(isSecure));
            Console.Write("publicKey {0} ", Convert.ToString(publicKey));
            Console.Write("privateKey {0} ", Convert.ToString(privateKey));
        }
        public string CryptPassword(string AConnectionString)
        {
            DbConnectionStringBuilder builder = new DbConnectionStringBuilder();
            builder.ConnectionString = AConnectionString;
            string lPassword = builder["Password"] as string;
            byte[] lBytes = Encoding.ASCII.GetBytes(lPassword);
            byte[] lCryptedBytes = rsa.Encrypt(lBytes, false);    
            builder["Password"] = GetString(lCryptedBytes);
            return builder.ConnectionString;
        }

        public string DeCryptPassword(string AConnectionString)
        { 
            DbConnectionStringBuilder builder = new DbConnectionStringBuilder();
            builder.ConnectionString = AConnectionString;
            string lPassword = builder["Password"] as string;
            byte[] lBytes = GetBytes(lPassword);
            byte[] lCryptedBytes = rsa.Decrypt(lBytes, false);
            builder["Password"] = Encoding.ASCII.GetString(lCryptedBytes);
            return builder.ConnectionString;
        }
        public void SaveParamToConfig(string AParamName, string AValue)
        {
            Configuration currentConfig = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            currentConfig.AppSettings.Settings[AParamName].Value = AValue;
            currentConfig.Save(ConfigurationSaveMode.Modified);
            ConfigurationManager.RefreshSection("appSettings");
            return;
        }
        public void SaveParamToConfig(string AParamName, Boolean AValue)
        {
            SaveParamToConfig(AParamName, Convert.ToString(AValue));
            return;
        }
        public void SaveToConfigConnetionString(string AValue)
        {     
            Configuration currentConfig = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            currentConfig.AppSettings.Settings["Login"].Value = AValue;
            currentConfig.Save(ConfigurationSaveMode.Modified);
            ConfigurationManager.RefreshSection("appSettings");
            return;
        }

        public void SaveToConfigIsSecure(Boolean AValue)
        {
            Configuration currentConfig = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            currentConfig.AppSettings.Settings[isSecureParamName].Value = Convert.ToString(AValue);
            currentConfig.Save(ConfigurationSaveMode.Modified);            
            ConfigurationManager.RefreshSection("appSettings");
            return;
        }
        public string GetConnectionString()
        {
            DbConnectionStringBuilder lBuilder = new DbConnectionStringBuilder();
            lBuilder.ConnectionString = ConnectionString;
            lBuilder[CryptoRAS128Const.CON_STR_PASSWORD] = Password;
            lBuilder[CryptoRAS128Const.CON_STR_USER_NAME] = Login;

            string lStr = lBuilder.ConnectionString;
            return lStr;
        }
        public void ProcessParams()
        {            
            string lPassword = Password;

            if (isSecure)
            {
                Password = CryptStr(lPassword);
                lPassword = Password;
                SaveParamToConfig(PasswordParamName, Password);
                SaveToConfigIsSecure(false);
            }
            Password = DeCryptStr(lPassword);
            return;
        }

        public void LoadPrarams()
        {
            var appSettings = ConfigurationManager.AppSettings;
            string lStr =  appSettings[isSecureParamName];
            isSecure = Convert.ToBoolean(lStr);
            Login = appSettings[LoginParamName];
            Password = appSettings[PasswordParamName];

            ConnectionString = ConfigurationManager.ConnectionStrings[ConnectionStringParamName].ConnectionString;
            

        }
        public void GenerateKeys(ref string APublicKey, ref string APrivateKey)
        {
            RSACryptoServiceProvider TmpRSACryptoServiceProvider = new RSACryptoServiceProvider();
            APublicKey = TmpRSACryptoServiceProvider.ToXmlString(false);
            APrivateKey = TmpRSACryptoServiceProvider.ToXmlString(true);            
            return;
        }
        public void GenerateKeysInToFiles(string APathToPublicKey, string APathToPrivateKey)
        {
            if (string.IsNullOrWhiteSpace(APathToPrivateKey))
            {
                throw new Exception("Path to private key file is empty.");
            }

            if (string.IsNullOrWhiteSpace(APathToPublicKey))
            {
                throw new Exception("Path to public key file is empty.");
            }
            string lPathToPublicKey = "";
            string lPathToPrivateKey = "";
            GenerateKeys(ref lPathToPublicKey, ref lPathToPrivateKey);
            File.WriteAllText(APathToPublicKey, lPathToPublicKey);
            File.WriteAllText(APathToPrivateKey, lPathToPrivateKey);
            return;
        }

        public void LoadPublicKeyFromFile(string APathToFile)
        {
            string PublicKey = File.ReadAllText(APathToFile);
            rsa.FromXmlString(PublicKey);
            return;
        }

        public void LoadPrivateKeyFromFile(string APathToFile)
        {
            string PrivateKey = File.ReadAllText(APathToFile);
            rsa.FromXmlString(PrivateKey);
            return;
        }

        public CryptoRAS128Helper() {
            CspParameters cspParams;
            cspParams = new CspParameters(CryptoRAS128Const.PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = CryptoRAS128Const.CONTAINER_NAME;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName = CryptoRAS128Const.PROVIDER_NAME;
            rsa = new RSACryptoServiceProvider();
            rsa.KeySize = CryptoRAS128Const.KEY_SIZE;
            isSecureParamName = "IsSecure";
            PasswordParamName = "Password";
            LoginParamName = "Login";
            ConnectionStringParamName = "Test";
        }

    }
}
