using System;
using System.Security.Cryptography;

namespace CJLU2.Utils
{
    /**
     * 参考 https://github.com/is0xb/NetKeeperDialer/blob/master/NetKeeperDialer/NKAccount.cs
     * 参考 https://blog.csdn.net/qq_33212020/article/details/52972188
     * 参考 https://github.com/richard1122/netkeeper-windows/blob/master/SXWindows/SXEncryption.cpp
     **/

    /** 
     * 示例：
     * using CJLU2.Utils;
     * NetKeeper.calculateRealUsername("18888888888" + "@JLXQ.XY");
     **/
    public class NetKeeper
    {
        public static string calculateRealUsername(string username)
        {
            return "\r\n" + GetSig1() + GetSig2(username) + username;
        }

        private static string GetTimeString()
        {
            int timediv5 = (int) DateTimeOffset.Now.ToUnixTimeSeconds() / 5;
            string timestr = "";
            for (int i = 0; i != 4; ++i)
            {
                timestr += (char)((timediv5 >> ((3 - i) * 8)) & 0xFF);
            }
            return timestr;
        }

        private static string GetSig1()
        {
            string timestr = GetTimeString();
            byte[] temp = new byte[32];
            byte[] timechar = new byte[4];
            for (int i = 0; i != 4; i++)
            {
                timechar[i] = (byte)timestr[i];
            }
            for (int i = 0; i < 32; i++)
            {
                temp[i] = (byte)(timechar[(31 - i) >> 3] & 1);
                timechar[(31 - i) >> 3] = (byte)(timechar[(31 - i) >> 3] >> 1);
            }
            byte[] timeHash = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                timeHash[i] = (byte)(
                    temp[i] * 128 +
                    temp[4 + i] * 64 +
                    temp[8 + i] * 32 +
                    temp[12 + i] * 16 +
                    temp[16 + i] * 8 +
                    temp[20 + i] * 4 +
                    temp[24 + i] * 2 +
                    temp[28 + i]);
            }
            temp[1] = (byte)((timeHash[0] & 3) << 4);
            temp[0] = (byte)((timeHash[0] >> 2) & 0x3F);
            temp[2] = (byte)((timeHash[1] & 0xF) << 2);
            temp[1] = (byte)((timeHash[1] >> 4 & 0xF) + temp[1]);
            temp[3] = (byte)(timeHash[2] & 0x3F);
            temp[2] = (byte)(((timeHash[2] >> 6) & 0x3) + temp[2]);
            temp[5] = (byte)((timeHash[3] & 3) << 4);
            temp[4] = (byte)((timeHash[3] >> 2) & 0x3F);
            string sig1 = "";
            for (int i = 0; i < 6; i++)
            {
                int tp = temp[i] + 0x020;
                if (tp >= 0x40)
                {
                    tp++;
                }
                sig1 += (char)(tp);
            }
            return sig1;
        }

        private static string GetSig2(string account)
        {
            byte[] dat = new byte[32];
            int ptr = 0;
            string timestr = GetTimeString();
            string namestr = account.Substring(0, account.IndexOf('@'));
            string radius = "singlenet01";
            for (int i = 0; i < timestr.Length; i++)
            {
                dat[ptr] = (byte)timestr[i];
                ptr++;
            }
            for (int i = 0; i < namestr.Length; i++)
            {
                dat[ptr] = (byte)namestr[i];
                ptr++;
            }
            for (int i = 0; i < radius.Length; i++)
            {
                dat[ptr] = (byte)radius[i];
                ptr++;
            }
            byte[] md5 = new MD5CryptoServiceProvider().ComputeHash(dat, 0, ptr);
            string sig2 = md5[0].ToString("x2");
            return sig2;
        }
    }
}
