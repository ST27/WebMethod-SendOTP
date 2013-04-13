using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Services;
using System.Text;
using System.Globalization; 



using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Configuration;
using System.Web.Security;
using System.Collections;
using System.Security.Cryptography;
using System.Net;
using System.Net.Mail;
using System.Numerics;
//using System.Web.Mail;
//using System.Net.NetworkCredential;



[WebService(Namespace = "http://tempuri.org/")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
// Pour autoriser l'appel de ce service Web depuis un script à l'aide d'ASP.NET AJAX, supprimez les marques de commentaire de la ligne suivante. 
// [System.Web.Script.Services.ScriptService]

public class Service : System.Web.Services.WebService
{

    static String steps;
    static String steps2;
    static public long X = 60;
    static public String returnDig;
    static public String pin;
    public static int count = 0;
    public static String IMEI;
    public static long algo;
    public static long longSeed;

    public Service()
    {

    }

    [WebMethod(EnableSession = true)]
    public void Initialize(String pin0, long X0, String returnDig0, int count0, String IMEI0,long algo0,long longSeed0)
    {
        IMEI = IMEI0;
        count = count0;
        X = X0;
        returnDig = returnDig0;
        pin = pin0;
        algo = algo0;
        longSeed = longSeed0;

    }

    [WebMethod(EnableSession = true)]
    public String calculHOTP()
    {

        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
        return generateHOTP(encoding.GetBytes(pin + IMEI), count, 6);


    }


    [WebMethod(EnableSession = true)]

    public String generateTOTP(int n)
    {

        long T0 = 0;

        DateTime d = DateTime.Now;
        TimeSpan diff = (d - new DateTime(1970, 01, 01));
        long i = (long)diff.TotalSeconds;
        //Console.Write(i + "\n");
        long[] testTime = { i };
        for (int j = 0; j < testTime.Length; j++)
        {
            long T = (i - T0) / X;
            long T2 = ((i - T0) / X) - 1;
            steps = T.ToString("X2");
            Console.Write(steps + "\n");
            steps2 = T2.ToString("X2");
            while (steps.Length < 16) steps = "0" + steps;
            while (steps2.Length < 16) steps2 = "0" + steps2;

        }

        switch (n)
        {

            case 1: return calculTOTP(pin + IMEI, steps);
            case 2: return calculTOTP(pin + IMEI, steps2);
            default: return "  ";
        }
    }

    [WebMethod(EnableSession = true)]
    public bool CompareTOTP(String otp)
    {
        if (generateTOTP(1).Equals(otp) || generateTOTP(2).Equals(otp))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    [WebMethod(EnableSession = true)]
    public string CompareHOTP(String otp, int n)
    {
        
        int i=0;
        int c = 0;
        int countinit = count;

        

        while(i<n && c!=1)
        {
            if (calculHOTP().Equals(otp))
            {
                // pin et count sont lues normalement à partir de la BD
                c = 1;
                count = count + i;
            }
            else
            {
                count++;
            }
        i++;
        }
        int decalage = count - countinit;
        if (c == 1) { return "true  -" + decalage ; }
        else return "false";


    }
    [WebMethod(EnableSession = true)]
    public void SendSMS(String num)
    {
        String strCmdText;
				// you must install gammu and configure it with your GSM modem or mobile device to use this function 
        strCmdText = "echo Votre code d'authentification" + generateTOTP(1) + "|gammu -c C:/Users/soufianet/gammurc sendsms text +" + num;

        System.Diagnostics.Process.Start("CMD.exe", "/c " + strCmdText);
    }

    [WebMethod(EnableSession = true)]
    public void send_email(string recepteur)
    {
        MailMessage msg = new MailMessage();

        // Expéditeur (obligatoire). Notez qu'on peut spécifier le nom
        msg.From = new MailAddress("test@gmail.com");

        msg.To.Add(new MailAddress(recepteur));
        msg.Subject = "password";
        msg.Body = "Votre code d'authentification " + generateTOTP(1);

        // Fichier joint si besoin (facultatif)
        //msg.Attachments.Add(new Attachment(@"c:\fichierjoint.txt"));

        // Envoi du message SMTP

        SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
        client.EnableSsl = true;
        client.UseDefaultCredentials = false;
        client.Credentials = new NetworkCredential("test@gmail.com", "testtest");

        // Envoi du mail
        client.Send(msg);
       

    }




    /* ocrasuite doit être écrite dans la forme suivante  : OCRA-1:HOTP-SHA512-6:QN08-PSHA1  */
    [WebMethod(EnableSession = true)]
    public String generateOCRA(String ocraSuite, String question)
    {

        int codeDigits = 0;
        String crypto = null;
        String result = null;
        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
        int ocraSuiteLength = (encoding.GetBytes(ocraSuite)).Length;
        int questionLength = 0;
        int passwordLength = 0;
        int cry = 0;

        // The OCRASuites components
        String CryptoFunction = ocraSuite.Split(':')[1];
        String DataInput = ocraSuite.Split(':')[2];

        if (CryptoFunction.ToLower().IndexOf("sha1") > 1)
        {
            crypto = "HmacSHA1";
            cry = 1;
        }
        if (CryptoFunction.ToLower().IndexOf("sha256") > 1)
        {
            crypto = "HmacSHA256";
            cry = 256;
        }
        if (CryptoFunction.ToLower().IndexOf("sha512") > 1)
        {
            crypto = "HmacSHA512";
            cry = 512;
        }
        // How many digits should we return
        codeDigits = int.Parse(CryptoFunction.Substring(CryptoFunction.LastIndexOf("-") + 1));


        // Question - always 128 bytes
        /* if (DataInput.ToLower().StartsWith("q") ||
                 (DataInput.ToLower().IndexOf("-q") >= 0))
         {
             while (question.Length < 256)
                 question = question + "0";
         */
        questionLength = 128;


        // Password - sha1
        /*if (DataInput.ToLower().IndexOf("psha1") > 1)
        {
            while (password.Length < 40)
                password = "0" + password;*/
        passwordLength = 20;





        // Remember to add "1" for the "00" byte delimiter
        byte[] msg = new byte[ocraSuiteLength +
                      questionLength +
                      passwordLength +
                      1];


        // Put the bytes of "ocraSuite" parameters into the message
        byte[] bArray = /*hexStr2Bytes*/encoding.GetBytes(ocraSuite);
        System.Array.Copy(bArray, 0, msg, 0, bArray.Length);

        // Delimiter
        msg[bArray.Length] = 0x00;


        // Put the bytes of "question" to the message
        // Input is text encoded
        if (questionLength > 0)
        {
            bArray = hexStr2Bytes(question);
            System.Array.Copy(bArray, 0, msg, ocraSuiteLength + 1, bArray.Length);
        }

        // Put the bytes of "password" to the message
        // Input is HEX encoded


        if (passwordLength > 0)
        {
            bArray = hexStr2Bytes(pin);
            System.Array.Copy(bArray, 0, msg, ocraSuiteLength + 1 + questionLength, bArray.Length);

        }


        // Put the bytes of "time" to the message
        // Input is text value of minutes

        bArray = hexStr2Bytes(IMEI);

        byte[] hash = hmac_sha(bArray, msg, cry);

        // put selected bytes into result int
        int offset = hash[hash.Length - 1] & 0xf;

        int binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = otp.ToString();
        while (result.Length < codeDigits)
        {
            result = "0" + result;
        }
        return result;


    }

    private static byte[] hexStr2Bytes(String hex)
    {
        //BigInteger dec = BigInteger.Parse("10" + hex, System.Globalization.NumberStyles.HexNumber);
        int puissance = 1;
        int s = 0;
        int decim = 0;
        String hexfinal = CultureInfo.CurrentCulture.NumberFormat.NumberDecimalSeparator;

        hexfinal = "10" + hex;

        for (s = 0; s < hexfinal.Length - 1; s++)
        {
            puissance = 1;
            for (int j = 0; j < hexfinal.Length - 1 - s; j++)
            {
                puissance = puissance * 16;
            }
            decim = decim + (int.Parse(hexfinal[s].ToString()) * puissance);

        }

        decim = decim + int.Parse(hexfinal[hexfinal.Length - 1].ToString());
        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
        byte[] bArray = encoding.GetBytes(decim.ToString());
        byte[] ret = new byte[bArray.Length - 1];
        /*for (int i = 0; i < ret.Length; i++)
            ret[i] = bArray[i + 1];*/
        System.Array.Copy(bArray, 1, ret, 0, ret.Length);
        return ret;
    }

    [WebMethod(EnableSession = true)]
    public String calculTOTP(String key, String time)
    {

        int codeDigits = int.Parse(returnDig);
        String result = null;
        while (time.Length < 16)
            time = "0" + time;
        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
        byte[] msg = encoding.GetBytes(time);
        byte[] k = encoding.GetBytes(key);
        byte[] hash = hmac_sha(k, msg);
        int offset = hash[hash.Length - 1] & 0xf;

        int binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = otp.ToString();
        while (result.Length < codeDigits)
        {
            result = "0" + result;
        }
        return result;
    }
    private static int[] DIGITS_POWER
        // 0 1  2   3    4     5      6       7        8
     = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };


    [WebMethod(EnableSession = true)]
    private static byte[] hmac_sha(byte[] keyBytes, byte[] text, int crypto)
    {
        if (crypto == 1)
        {
            HMACSHA1 hmac = new HMACSHA1(keyBytes);
            byte[] bc = hmac.ComputeHash(text);
            return bc;
        }
        else if (crypto == 256)
        {
            HMACSHA256 hmac = new HMACSHA256(keyBytes);
            byte[] bc = hmac.ComputeHash(text);
            return bc;
        }
        else if (crypto == 512) { HMACSHA512 hmac = new HMACSHA512(keyBytes); byte[] bc = hmac.ComputeHash(text); return bc; }
        else return null;
    }

    [WebMethod(EnableSession = true)]
    private static byte[] hmac_sha(byte[] keyBytes, byte[] text)
    {
        HMACSHA512 hmac = new HMACSHA512(keyBytes);
        byte[] bc = hmac.ComputeHash(text);
        return bc;
    }
    [WebMethod(EnableSession = true)]
    static private String generateHOTP(byte[] secret, long movingFactor,
        int codeDigits)
    {
        // put movingFactor value into text byte array
        String result = null;
        byte[] text = new byte[8];
        for (int i = text.Length - 1; i >= 0; i--)
        {
            text[i] = (byte)(movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        byte[] hash = hmac_sha(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.Length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = (int)(binary % DIGITS_POWER[codeDigits]);
        //     int otp = binary % DIGITS_POWER[codeDigits];
        result = otp.ToString();
        while (result.Length < codeDigits)
        {
            result = "0" + result;
        }
        return result;
    }
    public static int randomNumbers(/*int returnDigits*/ int max /*String algo*/)
    {
        Random r = new Random();
        int rndNums;
        // String OCRA = "OCRA-1:HOTP-" + "-"  + ":QN08-PSHA1";
        rndNums = r.Next(max);
        //return OCRA + "-" + rndNums;
        return rndNums;
    }

    [WebMethod]
    public String generateChallenge()
    {
        long g = 0;
        string max = "";
        String s = "";
        if (algo == 0)
        {
            do
            {
                g = randomNumbers(4);
            }
            while (g < 1);
            algo = g;
        }


        for (int i = 0; i < longSeed; i++)
        {
            max = max + "9";
        }

        s = algo + "-" + returnDig + "-" + randomNumbers(int.Parse(max));

        return s;
    }
}
