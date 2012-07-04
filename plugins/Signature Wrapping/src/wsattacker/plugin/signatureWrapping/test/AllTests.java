package wsattacker.plugin.signatureWrapping.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import wsattacker.plugin.signatureWrapping.test.singletests.AxisAnalyserTest;
import wsattacker.plugin.signatureWrapping.test.singletests.OptionPayloadTest;
import wsattacker.plugin.signatureWrapping.test.singletests.SchemaNullTest;
import wsattacker.plugin.signatureWrapping.test.singletests.SchemaTest;
import wsattacker.plugin.signatureWrapping.test.singletests.SignatureManagerTest;
import wsattacker.plugin.signatureWrapping.test.singletests.SignerTest;
import wsattacker.plugin.signatureWrapping.test.singletests.WrappingOracleTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathAnalyserTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathAttributeWeaknessPostProcessTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathAttributeWeaknessTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathDescendantWeaknessAllPossibilitiesTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathDescendantWeaknessTest;
import wsattacker.plugin.signatureWrapping.test.singletests.XPathNamespaceInjectionWeaknessTest;

@RunWith(Suite.class)
@SuiteClasses(
{ AxisAnalyserTest.class, SchemaTest.class, SchemaNullTest.class, SignatureManagerTest.class, SignerTest.class, WrappingOracleTest.class, XPathDescendantWeaknessAllPossibilitiesTest.class, XPathDescendantWeaknessTest.class, XPathAttributeWeaknessPostProcessTest.class, XPathAttributeWeaknessTest.class, XPathNamespaceInjectionWeaknessTest.class, OptionPayloadTest.class, XPathAnalyserTest.class})
public class AllTests
{

}
