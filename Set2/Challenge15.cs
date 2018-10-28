using System;

namespace cryptoPalsSet2
{
    partial class Program
    {
        static bool challenge15(byte[] data)
        {
            int paddValue = data[data.Length - 1];
            for(int a = data.Length - 2; a > data.Length - paddValue; a--)
            {
                if(data[a] == paddValue)
                {
                    continue;
                }
                else
                {
                    throw new Exception("Padding is incorrect. This can be for one of two reasons:" +
                                        "\n1 - Padding is of inconsistent values" +
                                        "\n2 - Padding is of incorrect length (e.g. padding is length 4 and of value 2");
                }
            }
            return true;
        }
    }
}
