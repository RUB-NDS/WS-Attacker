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

import com.google.common.collect.Lists;
import java.util.List;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.Position;
import wsattacker.library.intelligentdos.success.Efficiency;

/**
 * @author Christian Altmeier
 */
public class SuccessfulAttack
{
    private final DoSAttack doSAttack;

    private Position position;

    private PayloadPosition payloadPosition;

    private final CommonParamItem paramItem;

    private Efficiency efficiency = Efficiency.unknown;

    private double ratio;

    private String xmlWithPlaceholder;

    private String untamperedContent;

    private String tamperedContent;

    private List<Metric> untamperedMetrics = Lists.newArrayList();

    private List<Metric> tamperedMetrics = Lists.newArrayList();

    private List<Metric> testProbeMetrics = Lists.newArrayList();

    public SuccessfulAttack( DoSAttack doSAttack, CommonParamItem paramItem )
    {
        this.doSAttack = doSAttack;
        this.paramItem = paramItem;
    }

    public DoSAttack getDoSAttack()
    {
        return doSAttack;
    }

    public Position getPosition()
    {
        return position;
    }

    public void setPosition( Position position )
    {
        this.position = position;
    }

    public PayloadPosition getPayloadPosition()
    {
        return payloadPosition;
    }

    public void setPayloadPosition( PayloadPosition payloadPosition )
    {
        this.payloadPosition = payloadPosition;
    }

    public CommonParamItem getParamItem()
    {
        return paramItem;
    }

    public Efficiency getEfficiency()
    {
        return efficiency;
    }

    public void setEfficiency( Efficiency efficiency )
    {
        this.efficiency = efficiency;
    }

    public List<Metric> getTestProbeMetrics()
    {
        return testProbeMetrics;
    }

    public void setTestProbeMetrics( List<Metric> testProbeMetrics )
    {
        this.testProbeMetrics = testProbeMetrics;
    }

    public double getRatio()
    {
        return ratio;
    }

    public void setRatio( double ratio )
    {
        this.ratio = ratio;
    }

    public String getXmlWithPlaceholder()
    {
        return xmlWithPlaceholder;
    }

    public void setXmlWithPlaceholder( String xmlWithPlaceholder )
    {
        this.xmlWithPlaceholder = xmlWithPlaceholder;
    }

    public String getUntamperedContent()
    {
        return untamperedContent;
    }

    public void setUntamperedContent( String untamperedContent )
    {
        this.untamperedContent = untamperedContent;
    }

    public String getTamperedContent()
    {
        return tamperedContent;
    }

    public void setTamperedContent( String tamperedContent )
    {
        this.tamperedContent = tamperedContent;
    }

    public List<Metric> getUntamperedMetrics()
    {
        return untamperedMetrics;
    }

    public void setUntamperedMetrics( List<Metric> untamperedMetrics )
    {
        this.untamperedMetrics = untamperedMetrics;
    }

    public List<Metric> getTamperedMetrics()
    {
        return tamperedMetrics;
    }

    public void setTamperedMetrics( List<Metric> tamperedMetrics )
    {
        this.tamperedMetrics = tamperedMetrics;
    }

    public List<Metric> getTestProbes()
    {
        return testProbeMetrics;
    }

    public void setTestProbes( List<Metric> testProbeMetrics )
    {
        this.testProbeMetrics = testProbeMetrics;
    }

    @Override
    public String toString()
    {
        return String.format( "SuccessfulAttack[dos=%s, position=%s, payload=%s]", doSAttack.getName(), position,
                              payloadPosition );
    }

}
