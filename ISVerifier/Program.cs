using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

public class Program
{
    private static int _dataCounter = 0;
    private static string _receivedPublicKeyXml;
    private static string _receivedMessage;
    private static byte[] _receivedSignature;
    private static DigitalSignature _digitalSignature = new DigitalSignature();

    public static void Main()
    {
        SocketServer socketServer = new SocketServer();
        socketServer.DataReceived += HandleData;
        socketServer.StartListening(9001);
    }

    private static void HandleData(object sender, byte[] data)
    {
        if (_dataCounter == 0)
        {
            _receivedPublicKeyXml = Encoding.UTF8.GetString(data);
            Console.WriteLine("Received Public Key (XML):\n" + _receivedPublicKeyXml);
        }
        else if (_dataCounter == 1)
        {
            _receivedMessage = Encoding.UTF8.GetString(data);
            Console.WriteLine("Received Message:\n" + _receivedMessage);
        }
        else if (_dataCounter == 2)
        {
            _receivedSignature = data;
            Console.WriteLine("Received Signature (Base64):\n" + Convert.ToBase64String(_receivedSignature));

            // Deserialize the public key from XML
            RSAParameters publicKey;
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(_receivedPublicKeyXml);
                publicKey = rsa.ExportParameters(false);
            }

            bool isSignatureValid = _digitalSignature.VerifySignature(_receivedMessage, _receivedSignature, publicKey);
            Console.WriteLine($"Is the signature valid? {isSignatureValid}");

            // Reset the counter
            _dataCounter = -1;
        }

        _dataCounter++;
    }

}



