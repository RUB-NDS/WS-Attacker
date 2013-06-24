/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.function.postanalyze;

import java.awt.Window;
import wsattacker.plugin.signatureWrapping.function.postanalyze.gui.AnalysisDialog;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.plugin.signatureWrapping.SignatureWrapping;

public class SignatureWrappingAnalyzeFunction implements PluginFunctionInterface {

	SignatureWrapping plugin;

	public SignatureWrappingAnalyzeFunction(SignatureWrapping plugin) {
		this.plugin = plugin;
	}

	@Override
	public String getName() {
		return "Analyze XSW Responses";
	}

	@Override
	public boolean isEnabled() {
		return true; //plugin.isFinished(); // TODO: change to plugin.isFinished
	}

	@Override
	public Window getGuiWindow() {
		AnalysisDialog dialog = new AnalysisDialog(null, true);
//		AnalysisData testData = new AnalysisData();
//		testData.add("<eins/>", 1);
//		testData.add("<eins/>", 3);
//		testData.add("<eins/>", 5);
//		testData.add("<zwei/>", 2);
//		testData.add("<zwei/>", 4);
//		testData.add("<zwei/>", 6);
//		testData.add("<drei/>", 7);
//		testData.add("<drei/>", 8);
//		testData.add("<drei/>", 9);
//		plugin.setAnalysisData(testData);
		dialog.setSignatureWrappingPlugin(plugin);
		return dialog;
	}

}
