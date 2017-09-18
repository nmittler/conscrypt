package org.conscrypt;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.conscrypt.CipherEncryptBenchmark.Config;

public class TestMain {

  public static void main(String[] args) throws Exception {
    CipherEncryptBenchmark bm = new CipherEncryptBenchmark(new Config() {
      @Override
      public CipherEncryptBenchmark.BufferType bufferType() {
        return CipherEncryptBenchmark.BufferType.DIRECT_DIRECT;
      }

      @Override
      public CipherFactory cipherFactory() {
        return new CipherFactory() {
          @Override
          public Cipher newCipher(String transformation)
              throws NoSuchPaddingException, NoSuchAlgorithmException {
            return Cipher.getInstance(transformation, TestUtils.getConscryptProvider());
          }
        };
      }

      @Override
      public Transformation transformation() {
        return Transformation.AES_GCM_NO;
      }
    });

    while (true) {
    //for(int i = 0; i < 100; ++i) {
      bm.encrypt();
    }
  }
}
