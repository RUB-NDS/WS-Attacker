/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
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
