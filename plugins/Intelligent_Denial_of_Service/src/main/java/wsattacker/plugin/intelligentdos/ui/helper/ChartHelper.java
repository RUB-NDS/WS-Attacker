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
package wsattacker.plugin.intelligentdos.ui.helper;

import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.AxisLocation;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.BoxAndWhiskerRenderer;
import org.jfree.chart.renderer.xy.StandardXYItemRenderer;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.data.statistics.BoxAndWhiskerCategoryDataset;
import org.jfree.data.statistics.DefaultBoxAndWhiskerCategoryDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import wsattacker.library.intelligentdos.common.Metric;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;

/**
 * @author Christian Altmeier
 */
public class ChartHelper
{

    private static final double NANO_TO_MILLIES = 1000000.0;

    public static JFreeChart createDumyChart()
    {
        final BoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

        final CategoryAxis xAxis = new CategoryAxis( "Type" );
        final NumberAxis yAxis = new NumberAxis( "Value" );
        yAxis.setAutoRangeIncludesZero( false );
        final BoxAndWhiskerRenderer renderer = new BoxAndWhiskerRenderer();
        renderer.setFillBox( true );
        renderer.setMeanVisible( false );
        renderer.setMedianVisible( false );
        // renderer.setToolTipGenerator(new BoxAndWhiskerToolTipGenerator());
        final CategoryPlot plot = new CategoryPlot( dataset, xAxis, yAxis, renderer );

        return new JFreeChart( plot );
    }

    public static JFreeChart createOverlaidChart( SuccessfulAttack sa )
    {

        // create subplot 1...
        final XYSeries data1 = createDatasetResponseTime( RequestType.UNTAMPERED, sa.getUntamperedMetrics() );
        final XYSeries data2 = createDatasetResponseTime( RequestType.TAMPERED, sa.getTamperedMetrics() );
        final XYSeries data3 = createDatasetResponseTime( RequestType.TESTPROBES, sa.getTestProbes() );

        final XYSeriesCollection collection = new XYSeriesCollection();
        collection.addSeries( data1 );
        collection.addSeries( data2 );
        collection.addSeries( data3 );

        final XYItemRenderer renderer = new StandardXYItemRenderer();
        final NumberAxis rangeAxis1 = new NumberAxis( "duration in ms" );
        final XYPlot plot = new XYPlot( collection, new NumberAxis( "" ), rangeAxis1, renderer );
        plot.setRangeAxisLocation( AxisLocation.BOTTOM_OR_LEFT );
        renderer.setSeriesPaint( 0, Color.GREEN );
        renderer.setSeriesPaint( 1, Color.RED );
        renderer.setSeriesPaint( 2, Color.BLUE );

        // return a new chart containing the overlaid plot...
        return new JFreeChart( "", JFreeChart.DEFAULT_TITLE_FONT, plot, true );
    }

    private static XYSeries createDatasetResponseTime( RequestType requestType, List<Metric> metrics )
    {
        final XYSeries series = new XYSeries( requestType );

        int count = 1;
        for ( Metric metric : metrics )
        {
            double e = metric.getDuration() / NANO_TO_MILLIES;
            series.add( count, e );
            count++;
        }

        return series;
    }

    public static JFreeChart createWhiskerChart( SuccessfulAttack sa )
    {
        BoxAndWhiskerCategoryDataset boxandwhiskercategorydataset = createDataset( sa );
        final BoxAndWhiskerRenderer renderer = new BoxAndWhiskerRenderer();
        renderer.setMaximumBarWidth( 0.05 );
        renderer.setMeanVisible( false );
        renderer.setSeriesPaint( 0, Color.GREEN );
        renderer.setSeriesPaint( 1, Color.RED );
        renderer.setSeriesPaint( 2, Color.BLUE );

        NumberAxis numberAxis = new NumberAxis( "duration in ms" );
        CategoryPlot categoryplot =
            new CategoryPlot( boxandwhiskercategorydataset, new CategoryAxis( "" ), numberAxis, renderer );
        categoryplot.setDomainGridlinesVisible( true );
        categoryplot.setRangePannable( true );
        NumberAxis numberaxis = (NumberAxis) categoryplot.getRangeAxis();
        numberaxis.setStandardTickUnits( NumberAxis.createIntegerTickUnits() );
        JFreeChart jFreeChart = new JFreeChart( "", new Font( "SansSerif", Font.BOLD, 14 ), categoryplot, true );
        jFreeChart.removeLegend();
        return jFreeChart;
    }

    /**
     * @return
     */
    private static BoxAndWhiskerCategoryDataset createDataset( SuccessfulAttack sa )
    {
        DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

        add( dataset, RequestType.UNTAMPERED, sa.getUntamperedMetrics() );
        add( dataset, RequestType.TAMPERED, sa.getTamperedMetrics() );
        add( dataset, RequestType.TESTPROBES, sa.getTestProbeMetrics() );

        return dataset;
    }

    private static void add( DefaultBoxAndWhiskerCategoryDataset dataset, RequestType requestType, List<Metric> metrics )
    {
        List<Double> list = new ArrayList<Double>();
        for ( Metric metric : metrics )
        {
            double e = metric.getDuration() / NANO_TO_MILLIES;
            list.add( e );
        }

        dataset.add( list, "Series " + requestType, requestType );
    }
}
