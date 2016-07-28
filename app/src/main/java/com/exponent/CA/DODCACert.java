/*
MIT License

Copyright (c) 2016 United States Government

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Written by Christopher Williams, Ph.D. (cwilliams@exponent.com) & John Koehring (jkoehring@exponent.com)
*/

package com.exponent.CA;

import com.exponent.androidopacitydemo.ByteUtil;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Embedded implementation of CA/DODJITCCA_31.cer
 *
 * This implementation for demonstration only, this functionality would download cert in real app
 */


public class DODCACert
{
    public X509Certificate dodCaCert= null;

    public DODCACert()
    {
        ByteArrayInputStream bis=new ByteArrayInputStream(ByteUtil.hexStringToByteArray("3082058130820469a0" +
                "03020102020201f9300d06092a864886f70d01010505003060310b300906035504061302555331183016060355040a130f552e532" +
                "e20476f7665726e6d656e74310c300a060355040b1303446f44310c300a060355040b1303504b49311b301906035504031312446f" +
                "44204a49544320526f6f742043412032301e170d3132313033303030303030305a170d3138313033303030303030305a305c310b3" +
                "00906035504061302555331183016060355040a130f552e532e20476f7665726e6d656e74310c300a060355040b1303446f44310c" +
                "300a060355040b1303504b49311730150603550403130e444f44204a4954432043412d333130820122300d06092a864886f70d010" +
                "10105000382010f003082010a0282010100d2ec05504e3610e7b5387727b817632fc4dff898a1dea3ab63a15082ac9465f70f0edf" +
                "19e907cf356bc2cfdca8d857fdb3fea66fc8e5a9a2a93d05b75bacec4f75be2c8064050b785d4d295e2adb38a9e79d4f70e145698" +
                "c19b878e3628bb42e5e910b0b52a68c6e898d37d9a0b3dbf7d57009aa8211a7c09bd57c5378679b8fcb420b65da0ba4f3f3803dd1" +
                "b6fa80cf622f4e76d0c92954f75b9023cf0857819995b0fe7dd6c23a5c69490bd5dac2c09d6a5907925d2208710590f3b7e2fc629" +
                "0df218aa29bec898b789c96f212e4f2abe89f1d7bd9cb5a99325644a450ba16857bfd3e7e9b9fb84238c9495a44a68a1d3e5d741a" +
                "8013e23818e6a764485ffb0203010001a382024730820243301d0603551d0e0416041430062c2a921c5b36d7680f67025f015f2c5" +
                "08369301f0603551d23041830168014f9e03f8756ffd22180ba3d137ec54f54b0dfbc0230120603551d130101ff040830060101ff" +
                "020100300c0603551d2404053003800100300e0603551d0f0101ff04040302018630660603551d20045f305d300b0609608648016" +
                "502010b05300b0609608648016502010b09300b0609608648016502010b11300b0609608648016502010b12300b06096086480165" +
                "02010b13300c060a6086480165030201031a300c060a6086480165030201031b303f0603551d1f043830363034a032a030862e687" +
                "474703a2f2f63726c2e6e69742e646973612e6d696c2f63726c2f444f444a495443524f4f544341322e63726c3082012406082b06" +
                "0105050701010482011630820112304206082b060105050730028636687474703a2f2f63726c2e6e69742e646973612e6d696c2f6" +
                "97373756564746f2f444f444a495443524f4f544341325f49542e703763302e06082b060105050730018622687474703a2f2f6f63" +
                "73702e6e736e302e726376732e6e69742e646973612e6d696c30819b06082b0601050507300286818e6c6461703a2f2f63726c2e6" +
                "764732e6e69742e646973612e6d696c2f636e253364446f442532304a495443253230526f6f742532304341253230322532636f75" +
                "253364504b492532636f75253364446f442532636f253364552e532e253230476f7665726e6d656e742532636325336455533f637" +
                "26f73734365727469666963617465506169723b62696e617279300d06092a864886f70d010105050003820101007ab51324cc14df" +
                "67301cf24eb0690ce7ee1b1f2b42a155a9d99a91734ece542a7a97c6086704b41a34cababdfda0760c7544a3996e33375b4f89490" +
                "fc9c38b41885b037d8a1554612e2ca9bd1c611b9c450eb582f5825c42ee0d74c13996dc8c6903139f42b6e48bf8a7b1c8b2649748" +
                "d212e1be670b97415fe0cf028bf0fe4b18963286eff194124416bd582f9eafd2a8be9eac37d5cc4e3e0fee508196a892102c96ec0" +
                "76fee8f3218f1769ce7b5b6b464f2a6887bdfe3b8b1b91bc52e01522ec3b19321368499ec2245689bae407acadedc38f19d7885b6" +
                "5ce1a40bb4f41616a12edb3dde2bd643027b59e8e250faaf99064e25bdfa4b165923fa4438764b"));


        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            dodCaCert = (X509Certificate) cf.generateCertificate(bis);
            dodCaCert.checkValidity();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        }
    }

    public X509Certificate getDODCert()
    {
        return dodCaCert;
    }
}