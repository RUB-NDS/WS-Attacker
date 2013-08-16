/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.gui.component.pluginconfiguration.subcomponent;

import java.util.Arrays;
import javax.swing.JPanel;
import org.junit.Test;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.*;
import org.junit.Before;
import org.junit.BeforeClass;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.component.pluginconfiguration.controller.SelectedPluginController;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleChoice;
import wsattacker.main.plugin.option.OptionSimpleInteger;
import wsattacker.main.plugin.option.OptionSimpleText;
import wsattacker.main.plugin.option.OptionSimpleVarchar;

/**
 *
 * @author christian
 */
public class SelectedPluginTest {

	private static SelectedPlugin gui;
	private static AbstractPlugin plugin;
	private static JPanel panel;
	private static AbstractOption option1, option2, option3, option4, option5;
	private static SelectedPluginController controller;

	@BeforeClass
	public static void setUpBeforeClass() {
		option1 = new OptionSimpleBoolean("1", true);
		option2 = new OptionSimpleVarchar("2", "Value");
		option3 = new OptionSimpleInteger("3", 0);
		option4 = new OptionSimpleChoice("4", "Choice description");
		option5 = new OptionSimpleText("5", "Value");
	}

	@Before
	public void setUp() {
		gui = new SelectedPlugin();
		plugin = new DummyPlugin();
		plugin.setName(plugin.getName() + " TEST");
		controller = gui.getSelectedPluginController();
		controller.setSelectedPlugin(plugin);
		panel = gui.getOptionPanel();
	}

	@Test
	public void nonOverlappingOptions() {
		assertThat(0, is(panel.getComponentCount()));
		setAndCheck(option1);
		setAndCheck(option2, option3);
		setAndCheck(option1, option4, option5);
	}

	@Test
	public void overlappingOptions() {
		setAndCheck(option1);
		setAndCheck(option1, option2);
		setAndCheck(option1, option2, option3);
		setAndCheck(option1, option2, option3, option4);
		setAndCheck(option1, option2, option3, option4, option5);
		setAndCheck(option1, option2, option3, option4);
		setAndCheck(option1, option2, option3);
		setAndCheck(option1, option2);
		setAndCheck(option1);
		setAndCheck();
	}

	@Test
	public void changingOrder() {
		setAndCheck(option1, option2);
		setAndCheck(option2, option1);
		setAndCheck(option5, option4, option3, option2, option1);
		setAndCheck(option1, option3, option2, option5, option4);
	}

	@Test
	public void settingSingleOptions() {
		setAndCheck(option1, option2, option3);
		setOption(1, option5);
		checkOptions(option1, option5, option3);
		setOption(0, option4);
		checkOptions(option4, option5, option3);
		setOption(2, option1);
		checkOptions(option4, option5, option1);
	}

	@Test
	public void addingOptions() {
		setAndCheck(option2, option4);
		addOption(0, option1);
		checkOptions(option1, option2, option4);
		addOption(3, option5);
		checkOptions(option1, option2, option4, option5);
		addOption(2, option3);
		checkOptions(option1, option2, option3, option4, option5);
	}

	@Test
	public void changingPlugin() {
		setAndCheck(option1, option2);
		plugin = new DummyPlugin();
		plugin.setName(plugin.getName() + "TEST 2");
		setOptions(option3);
		controller.setSelectedPlugin(plugin);
		checkOptions(option3);

	}

	public AbstractOption getPanelOption(int index) {
		return ((OptionGUI) panel.getComponent(index)).getUsedOption();
	}

	public void setAndCheck(AbstractOption... options) {
		setOptions(options);
		checkOptions(options);
	}

	public void setOption(int index, AbstractOption option) {
		plugin.getPluginOptions().setOptions(index, option);
	}

	public void addOption(int index, AbstractOption option) {
		plugin.getPluginOptions().add(index, option);
	}

	public void setOptions(AbstractOption... options) {
		plugin.getPluginOptions().setOptions(Arrays.asList(options));
	}

	public void checkOptions(AbstractOption... options) {
		int length = options.length;
		for (int i = 0; i < length; ++i) {
			assertThat(panel.getComponentCount(), greaterThan(i));
			assertThat(options[i], sameInstance(getPanelOption(i)));
		}
		assertThat(panel.getComponentCount(), is(length));
	}
}
