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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.plugin.signatureWrapping.function.postanalyze.model;

import java.util.*;

/**
 * @author christian
 */
public class AnalysisDataCollector
{
    private Map<String, List<AnalysisData>> dataMap;

    public AnalysisDataCollector()
    {
        dataMap = new HashMap<String, List<AnalysisData>>();
    }

    /**
     * @return the data
     */
    public Map<String, ? extends List<AnalysisData>> getData()
    {
        return dataMap;
    }

    public List<AnalysisData> getDataEntry( String key )
    {
        return getData().get( key );
    }

    public void add( String key, int index, String response )
    {
        add( key, new AnalysisData( index, response ) );
    }

    public void add( String key, AnalysisData data )
    {
        if ( dataMap.containsKey( key ) )
        {
            dataMap.get( key ).add( data );
        }
        else
        {
            List<AnalysisData> newIndexSet = new ArrayList<AnalysisData>();
            newIndexSet.add( data );
            dataMap.put( key, newIndexSet );
        }
    }

}
