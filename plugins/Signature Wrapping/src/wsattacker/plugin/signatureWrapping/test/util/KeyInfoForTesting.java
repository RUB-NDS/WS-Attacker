package wsattacker.plugin.signatureWrapping.test.util;

// Key Information for Client Gatway (=alice)
public class KeyInfoForTesting implements KeyInfoInterface
{
  @Override
  public String getKeyStoreFileName()
  {
    return "keys/alice.jks";
  }

  @Override
  public String getKeyStorePassword()
  {
    return "storePwd";
  }

  @Override
  public String getEntityName()
  {
    return "alice";
  }

  @Override
  public String getEntityPassword()
  {
    return "keyPwd";
  }
}
