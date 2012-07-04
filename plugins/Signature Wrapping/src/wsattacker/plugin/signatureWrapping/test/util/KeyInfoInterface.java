package wsattacker.plugin.signatureWrapping.test.util;

/**
 * This Interace is used to get the needed Key Information for Signature creation/verification!
 * 
 */
public interface KeyInfoInterface
{

  public abstract String getKeyStoreFileName();

  public abstract String getKeyStorePassword();

  public abstract String getEntityName();

  public abstract String getEntityPassword();

}
