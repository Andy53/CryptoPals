using System;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static byte[] challenge9(byte[] data)
        {
            int padValue = 0;
            int padding = data.Length;

            //Check length needed to be padded
            while (padding % 32 != 0)
            {
                padding++;
                padValue++;
            }

            byte[] result = new byte[padding];
            Array.Copy(data, 0, result, 0, data.Length);

            //Pad with additional bytes
            for (int a = data.Length; a < padding; a++)
            {
                result[a] = (byte)padValue;
            }
            return result;
        }
    }
}
