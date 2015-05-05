/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Dennis Kupser
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

package wsattacker.library.xmlencryptionattack.detectionengine.detectionmanager;

import java.util.*;
import wsattacker.library.xmlencryptionattack.detectionengine.filter.base.AbstractDetectionFilter;

public class Pipeline
{
    private final HashMap<DetectFilterEnum, AbstractDetectionFilter> m_DetectionFilters;

    public Pipeline()
    {
        m_DetectionFilters = new HashMap<DetectFilterEnum, AbstractDetectionFilter>();
    }

    public AbstractDetectionFilter addFilerToPipline( AbstractDetectionFilter filter )
    {
        return m_DetectionFilters.put( filter.getFilterType(), filter );
    }

    public AbstractDetectionFilter removeFilerFromPipline( DetectFilterEnum filterType )
    {
        return m_DetectionFilters.remove( filterType );
    }

    public int getPipelineSize()
    {
        return m_DetectionFilters.size();
    }

    public AbstractDetectionFilter getPipelineFilter( DetectFilterEnum key )
    {
        return m_DetectionFilters.get( key );
    }

    public Iterator<AbstractDetectionFilter> getPipelineIterator()
    {
        return m_DetectionFilters.values().iterator();
    }

    public void removeAllFilerFromPipline()
    {
        m_DetectionFilters.clear();
    }
}