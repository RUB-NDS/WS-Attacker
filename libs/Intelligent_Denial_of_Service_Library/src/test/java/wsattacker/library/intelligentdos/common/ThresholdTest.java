/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.library.intelligentdos.common;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import wsattacker.library.intelligentdos.dos.DoSAttack;

/**
 * @author Christian Altmeier
 */
public class ThresholdTest
{

    @Test
	public void test() {
		DoSAttack minimum = mock(DoSAttack.class);
		when(minimum.getName()).thenReturn("test");
		List<DoSParam<?>> value = new ArrayList<>();
		DoSParam<Integer> dp = new DoSParam<Integer>("abc", 123);
		value.add(dp);
		when(minimum.getCurrentParams()).thenReturn(value);

		DoSAttack maximum = mock(DoSAttack.class);
		value = new ArrayList<>();
		when(maximum.getCurrentParams()).thenReturn(value);
		dp = new DoSParam<Integer>("abc", 456);
		value.add(dp);

		Threshold threshold = new Threshold(minimum, maximum);
		assertThat(threshold.toString(), is("Threshold[dosAttack=test, abc=123-456]"));
	}
}
