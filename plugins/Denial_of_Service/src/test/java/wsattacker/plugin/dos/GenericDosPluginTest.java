/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.plugin.dos;

import com.eviware.soapui.impl.wsdl.WsdlRequest;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin;
import wsattacker.plugin.dos.dosExtension.util.RequestResponsePairTest;
import wsattacker.plugin.dos.dosExtension.util.SoapTestRequest;

/**
 *
 * @author ianyo
 */
public class GenericDosPluginTest {

    public GenericDosPluginTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Tests if all mandatory options are set with correct name
     * if these are not set with the corresponding name the attack will throw
     * errors
     */
    public void testInitializePlugin(AbstractDosPlugin instance) {
        System.out.println(" - check for manadatory PluginOptions");
        instance.initializePlugin();
        PluginOptionContainer pluginOptions = instance.getPluginOptions();
        assertNotNull(pluginOptions.getByName("Param 1"));
        assertNotNull(pluginOptions.getByName("Param 2"));
        assertNotNull(pluginOptions.getByName("Param 3"));
        assertNotNull(pluginOptions.getByName("Param 4"));
        assertNotNull(pluginOptions.getByName("Param 5"));
        assertNotNull(pluginOptions.getByName("Param 6.0"));
        assertNotNull(pluginOptions.getByName("Param 6.1"));
        assertNotNull(pluginOptions.getByName("Param 7.0"));
        assertNotNull(pluginOptions.getByName("Param 7.1"));
        assertNotNull(pluginOptions.getByName("Param 7.2"));
        assertNotNull(pluginOptions.getByName("Message"));
    }

    /**
     * Test of getName method, of class TestDosAttack.
     */
    public void testGetName(AbstractDosPlugin instance) {
        System.out.println(" - getName");
        String result = instance.getName();
        assertTrue(result.length() > 0);
    }

    /**
     * Test of getDescription method, of class TestDosAttack.
     */
    public void testGetDescription(AbstractDosPlugin instance) {
        System.out.println(" - getDescription");
        String result = instance.getDescription();
        assertTrue(result.length() > 0);
    }

    /**
     * Test of getCountermeasures method, of class TestDosAttack.
     */
    public void testGetCountermeasures(AbstractDosPlugin instance) {
        System.out.println(" - getCountermeasures");
        String result = instance.getCountermeasures();
        assertTrue(result.length() > 0);
    }

    /**
     * Test of getAuthor method, of class TestDosAttack.
     */
    public void testGetAuthor(AbstractDosPlugin instance) {
        System.out.println(" - getAuthor");
        String result = instance.getAuthor();
        assertTrue(result.length() > 0);
    }

    /**
     * Test of getVersion method, of class TestDosAttack.
     */
    public void testGetVersion(AbstractDosPlugin instance) {
        System.out.println(" - getVersion");
        String result = instance.getVersion();
        assertTrue(result.length() > 0);
    }

    /**
     * Test of createTamperedRequest method, of class TestDosAttack.
     */
    public void testCreateTamperedRequest(AbstractDosPlugin instance) {
        System.out.println(" - createTamperedRequest");
        SoapTestRequest s = new SoapTestRequest();
        WsdlRequest w = s.getWsdlRequest();
        System.out.println(w.getEndpoint());
        RequestResponsePairTest requestResponsePairTest = new RequestResponsePairTest();
        requestResponsePairTest.setWsdlRequest(w);
        instance.setOriginalRequestResponsePair(requestResponsePairTest);

        // initialize first
        // has to be done to creates original request as String in textArea message option
        instance.initializePlugin();

        // set default SoapMessage Value in TextArea Field!
        instance.getOptionTextAreaSoapMessage().currentRequestContentChanged(w.getRequestContent(), "");

        // do actual request creation
        instance.createTamperedRequest();

        // We got here so we must have a valid Tampered request
        assertTrue(instance.getAttackPrecheck() == false || instance.getTamperedRequestObject().getXmlMessageLength() > 0);
//        if (instance.getAttackPrecheck() == false || instance.getTamperedRequestObject().getXmlMessageLength() > 0) {
//            assertTrue(true);
//        } else {
//            assertTrue(false);
//        }
    }
}
