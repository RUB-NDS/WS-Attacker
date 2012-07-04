package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.*;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.domToString;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.test.util.Signer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;

public class OptionPayloadTest
{
  
  private static Signer s;
  
  @BeforeClass
  public static void setUpBeforeClass() {
    s = new Signer(null);
  }
  
  @Test
  public void timestampTestInMilliseconds() throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    soap.setTimestamp(true,true);
    Element t = soap.getTimestamp();
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(t));
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(doc));
    
    OptionPayload o = new OptionPayload(null, "name", t, "timestampoption");
    
    assertTrue("Not a Timestamp Element:\n"+ domToString(t), o.isTimestamp());
    Element p = o.getPayloadElement();
    assertTrue("Expired: "+ domToString(p), s.verifyTimestamp(p));
  }
  
  @Test
  public void timestampTest() throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    soap.setTimestamp(true,false);
    Element t = soap.getTimestamp();
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(t));
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(doc));
    
    OptionPayload o = new OptionPayload(null, "name", t, "timestampoption");
    
    assertTrue("Not a Timestamp Element:\n"+ domToString(t), o.isTimestamp());
    Element p = o.getPayloadElement();
    assertTrue("Expired: "+ domToString(p), s.verifyTimestamp(p));
  }

}
