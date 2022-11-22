/// Gunnar Bachmann
/// CSCI.251 - Professor Jeremy Brown

using System.Net.Http;
using Newtonsoft.Json;
using System.Text;
using System.Numerics;

namespace Messenger
{
    ///<summary>
    /// Class to store public and private key.
    ///</summary>
    class Keys
    {
        public string? privateKey { get; set; }
        public string? publicKey { get; set; }
    }
    
    ///<summary>
    /// Class to store public key and email.
    ///</summary>
    class PublicKey
    {
        public string? email { get; set; }
        public string? key { get; set; }
    }

    ///<summary>
    /// Class to store private key and emails.
    ///</summary>
    class PrivateKey
    {
        public List<string>? email { get; set; }
        public string? key { get; set; }
    }

    ///<summary>
    /// Class to store key information/breakdown.
    ///</summary>
    class KeyInfo
    {
        public int e { get; }
        public BigInteger E { get; }
        public int n { get; }
        public BigInteger N { get; }
        public KeyInfo(int e, BigInteger E, int n, BigInteger N)
        {
            this.e = e;
            this.E = E;
            this.n = n;
            this.N = N;
        }
    }

    ///<summary>
    /// Class to store message response from server.
    ///</summary>
    class Message
    {
        public string? email { get; set; }
        public string? content { get; set; }
        // public string? messageTime { get; set; }
    }

    ///<summary>
    /// Program to use public key encryption to send secure messages to other users. 
    /// This will be a distributed system where keys will be stored on a server and you 
    /// will be able to secure messages to others using only their email address. 
    /// This is the client to encode and decode messages, and the messages will 
    /// all need to be smaller than the key length.
    ///</summary>
    class Messenger
    {
        private HttpClient client = new();
        private Keys keys = new();
        private readonly string privKeyFilename = "private.key";
        private readonly string pubKeyFilename = "public.key";
        private Messenger()
        {
            Keys keys = new Keys();
            HttpClient client = new HttpClient();
        }

        ///<summary>
        /// Main method for Messenger program. Takes input from user and
        /// performs the necessary steps to achieve specified process.
        ///</summary>
        ///<param name="args">Command line arguments.</param>
        public static void Main(string[] args)
        {
            if (args.Length == 0) {
                Console.WriteLine($"Invalid Input: {args.Length} arguments provided.\n");
                Help();
            }

            if (args[0] == "sendMsg" && args.Length != 3)
            {
                Console.WriteLine($"Invalid input: {args.Length} arguments provided for option {args[0]}.\n");
                Help();
            }
            else if (args[0] != "sendMsg" && args.Length != 2)
            {
                Console.WriteLine($"Invalid Input: {args.Length-1} arguments provided for option {args[0]}.\n");
                Help();
            }
            
            var messenger = new Messenger();
            
            if (args[0] == "keyGen")
            {
                var bits = Int32.Parse(args[1]);
                messenger.genKey(bits);
            }
            else if (args[0] == "sendKey")
            {
                var email = args[1];
                messenger.sendKey(email);
            }
            else if (args[0] == "getKey")
            {
                var email = args[1];
                messenger.getKey(email);
            }
            else if (args[0] == "sendMsg")
            {
                var email = args[1];
                var plaintext = args[2];
                messenger.sendMsg(email, plaintext);
            }
            else if (args[0] == "getMsg")
            {
                var email = args[1];
                messenger.getMsg(email);
            }
            else
            {
                Console.WriteLine($"Invalid option passed to program. Option passed: {args[0]}.\n");
                Help();
            }
        }

        ///<summary>
        /// Retrieve public key for a particular user
        ///</summary>
        ///<param name="email">Users public key you are retrieving.</param>
        private void getKey(string email)
        {
            try {
                string endpoint = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
                string filename = $"{email}.key";

                var response = client.GetStringAsync(endpoint);
                var responseObj = JsonConvert.DeserializeObject<PublicKey>(response.Result);
                string responseJson = JsonConvert.SerializeObject(responseObj, Formatting.Indented);
                File.WriteAllText(filename, responseJson);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("Exception Caught! Message: {0}\n", e.Message);
                Environment.Exit(0);
            }
        }

        ///<summary>
        /// Generate a keypair of size keysize bits (public and private keys)
        /// and store them locally on the disk (in files called public.key and
        /// private.key respectively), in the current directory.
        ///</summary>
        ///<param name="keysize">Amount of bits for size of public and private key</param>
        private void genKey(int keysize)
        {
            // Split keysize into two different values p and q
            var pSize = (int)((keysize / 2) - (keysize * 0.2));
            var qSize = keysize - pSize;

            // Generate p and q values
            var pGen = new PrimeGen(pSize);
            BigInteger p = pGen.Generate();
            var qGen = new PrimeGen(qSize);
            BigInteger q = qGen.Generate();

            // Get N
            BigInteger N = p*q;
            // Get N byte array
            byte[] ArrayN = N.ToByteArray();
            // Get n (4 bytes for the size of N), reverse array for big endian
            byte[] nArray = BitConverter.GetBytes(ArrayN.Length);
            Array.Reverse(nArray);

            // Get r (Phi(N))
            var r = (p - 1)*(q - 1);

            // Get E
            BigInteger E = new BigInteger(65537);
            // Get E byte array
            byte[] ArrayE = E.ToByteArray();
            // Get e (4 bytes for the size of E), reverse array for big endian 
            byte[] eArray = BitConverter.GetBytes(ArrayE.Length);
            Array.Reverse(eArray);

            // Get D
            var D = modInverse(E, r);
            // Get D array
            byte[] ArrayD = D.ToByteArray();
            // Get d (4 bytes for the size of D), reverse array for big endian
            byte[] dArray = BitConverter.GetBytes(ArrayD.Length);
            Array.Reverse(dArray);

            // Create public key byte array
            byte[] pubkeyBytes = new byte[eArray.Length + ArrayE.Length + nArray.Length + ArrayN.Length];
            Buffer.BlockCopy(eArray, 0, pubkeyBytes, 0, eArray.Length);
            Buffer.BlockCopy(ArrayE, 0, pubkeyBytes, eArray.Length, ArrayE.Length);
            Buffer.BlockCopy(nArray, 0, pubkeyBytes, eArray.Length+ArrayE.Length, nArray.Length);
            Buffer.BlockCopy(ArrayN, 0, pubkeyBytes, eArray.Length+ArrayE.Length+nArray.Length, ArrayN.Length);
            // Base64 encode public key byte array
            var encodedPubKey = Convert.ToBase64String(pubkeyBytes);

            // Create private key byte array
            byte[] privkeyBytes = new byte[dArray.Length + ArrayD.Length + nArray.Length + ArrayN.Length];
            Buffer.BlockCopy(dArray, 0, privkeyBytes, 0, dArray.Length);
            Buffer.BlockCopy(ArrayD, 0, privkeyBytes, dArray.Length, ArrayD.Length);
            Buffer.BlockCopy(nArray, 0, privkeyBytes, dArray.Length+ArrayD.Length, nArray.Length);
            Buffer.BlockCopy(ArrayN, 0, privkeyBytes, dArray.Length+ArrayD.Length+nArray.Length, ArrayN.Length);
            // Base64 encode private key byte array
            var encodedPrivKey = Convert.ToBase64String(privkeyBytes);

            var pubK = new PublicKey
            {
                key = encodedPubKey
            };
            string pubKeyJson = JsonConvert.SerializeObject(pubK, Formatting.Indented);
            File.WriteAllText(pubKeyFilename, pubKeyJson);


            var privK = new PrivateKey
            {
                key = encodedPrivKey
            };
            string privKeyJson = JsonConvert.SerializeObject(privK, Formatting.Indented);
            File.WriteAllText(privKeyFilename, privKeyJson);
        }

        ///<summary>
        /// Sends the public key that was generated in the keyGen phase
        /// to the server, with the email address given. The server will then
        /// register this email address as a valid receiver of messages.
        /// The private key will remain locally, but the email address that was given
        /// will be added to the private key for later validation.
        ///</summary>
        ///<param name="email">Email to be sent with public key to server</param>
        private void sendKey(string email)
        {
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
            try
            {
                // Read and deserialize private and public key files
                var pubKeyFileContent = File.ReadAllText(pubKeyFilename);
                var pubKeyObj = JsonConvert.DeserializeObject<PublicKey>(pubKeyFileContent);
                var privKeyFileContent = File.ReadAllText(privKeyFilename);
                var privKeyObj = JsonConvert.DeserializeObject<PrivateKey>(privKeyFileContent);

                // Check for null values to avoid Dereference of a possibly null reference warning
                if (pubKeyObj is null || pubKeyObj.key is null || privKeyObj is null)
                {
                    Console.WriteLine($"Encountered Issue: File is empty or there is no key value in file.\n");
                    Environment.Exit(0);
                }

                // Set public key email to be sent to server
                pubKeyObj.email = $"{email}";
                // Prep public key content to be sent to server
                var pubKeyString = JsonConvert.SerializeObject(pubKeyObj);
                var content = new StringContent(pubKeyString, Encoding.UTF8, "application/json");
                // Send public key to server via HTTP PUT
                var response = client.PutAsync(endpoint, content);
                // Check for successful status code from PUT
                if(!response.Result.IsSuccessStatusCode)
                {
                    Console.WriteLine("Program was unsuccessful when writing public key to server.\n");
                    Environment.Exit(0);
                }

                // Update Private Key email list and write back to private.key file
                if (privKeyObj.email is null)
                {
                    List<string> emailList = new List<string>();
                    emailList.Add(email);
                    privKeyObj.email = emailList;
                }
                else
                {
                    privKeyObj.email.Add(email);
                }
                string privKeyString = JsonConvert.SerializeObject(privKeyObj, Formatting.Indented);
                File.WriteAllText(privKeyFilename, privKeyString);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("Exception Caught! Message: {0}\n", e.Message);
                Environment.Exit(0);
            }
            Console.WriteLine("Key saved\n");
        }

        ///<summary>
        /// This will retrieve a message for a particular user. While it is
        /// possible to download messages for any user, you will only be able
        /// to decode messages for which you have the private key.
        ///</summary>
        ///<param name="email">User to retrieve messages for.</param>
        private void getMsg(string email)
        {
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Message/{email}";

            //1) Validate that you have a private key for the email being requested, if not, abort.
            var privKeyFileContent = File.ReadAllText(privKeyFilename);
            var privKeyObj = JsonConvert.DeserializeObject<PrivateKey>(privKeyFileContent);
            if (privKeyObj is null || privKeyObj.email is null || !privKeyObj.email.Contains(email) || privKeyObj.key is null)
            {
                Console.WriteLine($"Message(s) cannot be decoded.\n");
                Environment.Exit(0);
            }
            //2) Load the JSON object from the server into a local object
            try {
                var response = client.GetStringAsync(endpoint);
                // Console.WriteLine("TEMP PRINT - RESPONSE FROM SERVER: " + response.Result);
                var encodedMsg = JsonConvert.DeserializeObject<Message>(response.Result);
                if (encodedMsg is null || encodedMsg.content is null)
                {
                    Console.WriteLine("No message in server.\n");
                    Environment.Exit(0);
                }
                //3) Base64 decode the content property of the message object into a byte array
                byte[] msgBytes = Convert.FromBase64String(encodedMsg.content);
                //4) Convert the byte array to a big integer
                BigInteger C = new BigInteger(msgBytes);
                //5) Perform the decryption algorithm
                KeyInfo keyBreakdown = decodeKey(privKeyObj.key);
                var biP = BigInteger.ModPow(C, keyBreakdown.E, keyBreakdown.N);
                //6) Convert the results big integer to a byte array
                var bytesP = biP.ToByteArray();
                //7) Convert the byte a string
                var P = Encoding.UTF8.GetString(bytesP);
                //8) Display the message
                Console.WriteLine(P + "\n");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("Exception Caught! Message: {0}\n", e.Message);
            }
        }

        ///<summary>
        /// This will take a plaintext messages, encrypt it using the public key of
        /// the person you are sending it to, based on their email address. It will
        /// base64 encode the message before sending it to the server.
        ///</summary>
        ///<param name="email">User you are sending message to.</param>
        ///<param name="plaintext">Message you are sending.</param>
        private void sendMsg(string email, string plaintext)
        {
            string filename = $"{email}.key";
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Message/{email}";
            //1) Ensure you have the public key for the user you are sending a message to, if not, abort
            try
            {
                var pubKeyFileContent = File.ReadAllText(filename);
                var pubKeyObj = JsonConvert.DeserializeObject<PublicKey>(pubKeyFileContent);
                if (pubKeyObj is null || pubKeyObj.key is null)
                {
                    Console.WriteLine($"Key does not exist for {email}\n");
                    Environment.Exit(0);
                }
                //2) Take the plaintext message and covert it to a byte array
                byte[] pBytes = Encoding.UTF8.GetBytes(plaintext);
                //3) Take the resulting byte array and load it into a big integer
                BigInteger biP = new BigInteger(pBytes);
                //4) Perform the encryption algorithm
                KeyInfo keyBreakdown = decodeKey(pubKeyObj.key);
                BigInteger pEncrypted = BigInteger.ModPow(biP, keyBreakdown.E, keyBreakdown.N);
                //5) Convert the results big integer to a byte array
                byte[] pEncryptedBytes = pEncrypted.ToByteArray();
                //6) Base64 encode the byte array
                var pFinal = Convert.ToBase64String(pEncryptedBytes);
                //7) Load the base64 encoded byte array and the email message into message object and send it to the server
                Message msg = new Message();
                msg.email = email;
                msg.content = pFinal;
                string msgString = JsonConvert.SerializeObject(msg, Formatting.Indented);
                var content = new StringContent(msgString, Encoding.UTF8, "application/json");
                try
                {
                    var response = client.PutAsync(endpoint, content);
                    // Check for successful status code from PUT
                    if(!response.Result.IsSuccessStatusCode)
                    {
                        Console.WriteLine("Program was unsuccessful when writing message to server.\n");
                        Environment.Exit(0);
                    }
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine("Exception Caught! Message: {0}\n", e.Message);
                    Environment.Exit(0);
                }
            }
            catch (IOException)
            {
                Console.WriteLine($"Key does not exist for {email}\n");
                Environment.Exit(0);
            }
            Console.WriteLine("Message written\n");
        }

        ///<summary>
        /// Decode a given key and store breakdown of the key in KeyInfo object.
        ///</summary>
        private KeyInfo decodeKey(string key)
        {
            // Extract base64 key as a byte array
            byte[] bytes = Convert.FromBase64String(key);

            // e
            // - Read the first 4 bytes (these are big endian)
            // - Convert those bytes to an Int named e
            // byte[] eArray = new byte[4];
            // Array.Copy(bytes, 0, eArray, 0, 4);
            var eArray = bytes.Take(4).ToArray();
            Array.Reverse(eArray);
            var e = BitConverter.ToInt32(eArray);

            // E
            // - Skip the first 4 bytes, Read e number of Bytes as E (little endian)
            // - Convert E to a BigInteger
            // byte[] EArray = new byte[e];
            // Array.Copy(bytes, 4, EArray, 0, e);
            var EArray = bytes.Skip(4).Take(e).ToArray();
            var E = new BigInteger(EArray);

            // n
            // - Skip 4 + e bytes, read 4 bytes as n, Check the Endianess
            // - Convert n to an Int (big endian)
            // byte[] nArray = new byte[4];
            // Array.Copy(bytes, 4+e, nArray, 0, 4);
            var nArray = bytes.Skip(4+e).Take(4).ToArray();
            Array.Reverse(nArray);
            var n = BitConverter.ToInt32(nArray);

            // N
            // - Skip 4 + e + 4 bytes, read n Bytes into N (little endian)
            // byte[] NArray = new byte[n];
            // Array.Copy(bytes, 4+e+4, NArray, 0, n);
            var NArray = bytes.Skip(4+e+4).Take(n).ToArray();
            var N = new BigInteger(NArray);

            // return e, E, n, and N values into KeyInfo object
            return new KeyInfo(e, E, n, N);
        }

        ///<summary>
        /// Method to compute the mod inverse of two BigIntegers.
        ///</summary>
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a>0)
            {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t*x;
                v = x;
            }
            v %= n;
            if (v<0) v = (v+n)%n;
            return v;
        }

        ///<summary>
        /// Program help message. Outputs details relating to how a user should interact with the program,
        /// and then exits program.
        ///</summary>
        private static void Help()
        {
            Console.WriteLine("dotnet run <option> <other arguments>");
            Console.WriteLine("\t- option:\n\t\tEither keyGen, sendKey, getKey, sendMsg, getMsg.");
            Console.WriteLine("\t\tEach of these will accomplish a basic task.");
            Console.WriteLine("\t- other arguments:");
            Console.WriteLine("\t\tExtra command line arguments depending on the option used.");
            Console.WriteLine("\t\t- keyGen: keysize (ex: dotnet run keyGen 1024)");
            Console.WriteLine("\t\t- sendKey: email (ex: dotnet run sendKey test@cs.rit.edu)");
            Console.WriteLine("\t\t- getKey: email (ex: dotnet run getKey test@cs.rit.edu)");
            Console.WriteLine("\t\t- sendMsg: email, plaintext (ex: dotnet run sendMsg test@cs.rit.edu \"message to send\")");
            Console.WriteLine("\t\t- getMsg: email (ex: dotnet run getMsg test@cs.rit.edu)");
            Environment.Exit(0);
        }
    }
}