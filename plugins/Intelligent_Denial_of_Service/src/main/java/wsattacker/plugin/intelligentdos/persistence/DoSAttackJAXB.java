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
package wsattacker.plugin.intelligentdos.persistence;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.dos.DoSAttack;

import com.google.common.collect.Lists;

/**
 * @author Christian Altmeier
 */
@XmlRootElement
public class DoSAttackJAXB
{

    private String name;

    private List<DoSParamJAXB> params = Lists.newArrayList();

    public String getName()
    {
        return name;
    }

    public void setName( String name )
    {
        this.name = name;
    }

    public List<DoSParamJAXB> getParams()
    {
        return params;
    }

    public void setParams( List<DoSParamJAXB> params )
    {
        this.params = params;
    }

    public DoSAttack toDoSAttack()
    {
        List<DoSParam<?>> list = Lists.newArrayList();
        for ( DoSParamJAXB dp : params )
        {
            DoSParam<String> doSParam = new DoSParam<String>( dp.getDescription(), dp.getValue() );
            list.add( doSParam );
        }

        ResultDoSAttack doSAttack = new ResultDoSAttack( list );
        doSAttack.setName( name );

        return doSAttack;
    }

    public static DoSAttackJAXB fromDoSAttack( DoSAttack doSAttack )
    {
        DoSAttackJAXB da = new DoSAttackJAXB();
        da.setName( doSAttack.getName() );

        for ( DoSParam<?> doSParam : doSAttack.getCurrentParams() )
        {
            DoSParamJAXB dp = new DoSParamJAXB();
            dp.setDescription( doSParam.getDescription() );
            dp.setValue( doSParam.getValueAsString() );
            da.getParams().add( dp );
        }

        return da;
    }
}
