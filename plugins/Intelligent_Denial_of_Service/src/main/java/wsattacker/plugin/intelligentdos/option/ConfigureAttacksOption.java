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
package wsattacker.plugin.intelligentdos.option;

import java.util.Arrays;
import java.util.List;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.plugin.intelligentdos.ui.option.ConfigureAttacksOptionGUI_NB;

public class ConfigureAttacksOption
    extends AbstractOption
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private final ConfigureAttacksOptionGUI_NB configureAttacksOptionGUI_NB;

    /**
     * @param attacks
     * @param commonParamList
     * @param serverRecoveryTime
     * @param httpConnectionTimeout
     */
    public ConfigureAttacksOption( DoSAttack[] attacks, List<CommonParamItem> commonParamList, int serverRecoveryTime,
                                   int httpConnectionTimeout )
    {
        super( "IDoSConfigure", "" );
        configureAttacksOptionGUI_NB =
            new ConfigureAttacksOptionGUI_NB( attacks, commonParamList, serverRecoveryTime, httpConnectionTimeout );
    }

    @Override
    public boolean isValid( String value )
    {
        return false;
    }

    @Override
    public void parseValue( String value )
    {
    }

    @Override
    public String getValueAsString()
    {
        return null;
    }

    @Override
    public OptionGUI createOptionGUI()
    {

        return configureAttacksOptionGUI_NB;
    }

    public DoSAttack[] getAttacks()
    {
        final DoSAttack[] attacks = configureAttacksOptionGUI_NB.getAttacks();
        return Arrays.copyOf( attacks, attacks.length );
    }

    public List<CommonParamItem> getCommonParamList()
    {
        List<CommonParamItem> commonParamList = configureAttacksOptionGUI_NB.getCommonParamList();
        return commonParamList;
    }

    public int getServerRecoveryTime()
    {
        return configureAttacksOptionGUI_NB.getServerRecoveryTime();
    }

    public int getHttpConnectionTimeout()
    {
        return configureAttacksOptionGUI_NB.getHttpConnectionTimeout();
    }

}
