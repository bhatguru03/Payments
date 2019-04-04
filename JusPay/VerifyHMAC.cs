using System;
using System.Web;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using System.Collections.Specialized;
using System.Collections.Generic;

public class VerifyHMAC
{
	private string commonkey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
	
	 /*Method to varify HMAC signature after succesfull payment*/
    public void varifyURLStatus(string url)
    {

        NameValueCollection nvc = HttpUtility.ParseQueryString(url);
        /*To Test values */
        /*foreach (string key in nvc) {
                var value = nvc[key];
                System.Console.WriteLine(key +"=>"+ value);
            } */
        string StrOutPut = HttpUtility.UrlEncode("order_id") + "=" + HttpUtility.UrlEncode(nvc["order_id"]) + "&" + 
							HttpUtility.UrlEncode("status") + "=" + HttpUtility.UrlEncode(nvc["status"]) + "&" + 
							HttpUtility.UrlEncode("status_id") + "=" + HttpUtility.UrlEncode(nvc["status_id"]);
        string data = UpperCaseUrlEncode(StrOutPut);
        //string qS = HttpUtility.UrlDecode(CreateToken(data,commonkey));
        //System.Console.WriteLine(qS);
        if (HttpUtility.UrlDecode(nvc["signature"]) == CreateToken(data, commonkey))
        {
            System.Console.WriteLine("Matched");
            //Response is correct and Do whatever you want.... 
        }

    }
	
	/*Method to parse URL string  and return NameValueCollection*/
	public static  NameValueCollection ParseQueryString(string s)
    {
        NameValueCollection nvc = new NameValueCollection();

        // remove anything other than query string from url
        if(s.Contains("?"))
        {
            s = s.Substring(s.IndexOf('?') + 1);
        }

        foreach (string vp in Regex.Split(s, "&"))
        {
            string[] singlePair = Regex.Split(vp, "=");
            if (singlePair.Length == 2)
            {
                nvc.Add(singlePair[0], singlePair[1]);
            }
            else
            {
                // only one key with no value specified in query string
                nvc.Add(singlePair[0], string.Empty);
            }
        }

        return nvc;
    }

	/*Url is not Encoded properly when using only 'HttpUtility.UrlEncode'  you should just need to loop through the string and uppercase 
       only the two characters following a % sign. That'll keep your base64 data intact while messaging the encoded characters into the right 
        format */
	private static string UpperCaseUrlEncode(string s)
        {
          char[] temp = HttpUtility.UrlEncode(s).ToCharArray();
          for (int i = 0; i < temp.Length - 2; i++)
          {
            if (temp[i] == '%')
            {
              temp[i + 1] = char.ToUpper(temp[i + 1]);
              temp[i + 2] = char.ToUpper(temp[i + 2]);
            }
          }
          return new string(temp);
        }
		
		/*Reporducing signature using HMASHA256 Algorithm*/
	private static string CreateToken(string message, string secret)
        {
          secret = secret ?? "";
          var encoding = new System.Text.ASCIIEncoding();
          byte[] keyByte = encoding.GetBytes(secret);
          byte[] messageBytes = encoding.GetBytes(message);
          using (var hmacsha256 = new HMACSHA256(keyByte))
          {
            byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
            return Convert.ToBase64String(hashmessage);
          }
        }
	
}