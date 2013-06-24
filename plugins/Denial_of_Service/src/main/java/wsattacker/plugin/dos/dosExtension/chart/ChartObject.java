/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2012 Andreas Falkenberg
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
package wsattacker.plugin.dos.dosExtension.chart;

import java.awt.Color;
import java.awt.Font;
import java.awt.geom.Ellipse2D;
import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import java.util.Random;

import wsattacker.plugin.dos.dosExtension.logEntry.LogEntryInterval;
import wsattacker.plugin.dos.dosExtension.mvc.model.AttackModel;

import org.jfree.chart.ChartPanel;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.LegendItemCollection;
import org.jfree.chart.annotations.XYTextAnnotation;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickMarkPosition;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.block.BlockBorder;
import org.jfree.chart.block.BlockContainer;
import org.jfree.chart.block.BorderArrangement;
import org.jfree.chart.block.EmptyBlock;
import org.jfree.chart.labels.StandardXYToolTipGenerator;
import org.jfree.chart.plot.DatasetRenderingOrder;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.LineAndShapeRenderer;
import org.jfree.chart.renderer.category.MinMaxCategoryRenderer;
import org.jfree.chart.renderer.category.StandardBarPainter;
import org.jfree.chart.renderer.xy.StandardXYBarPainter;
import org.jfree.chart.renderer.xy.StandardXYItemRenderer;
import org.jfree.chart.renderer.xy.XYBarPainter;
import org.jfree.chart.renderer.xy.XYBarRenderer;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.renderer.xy.XYSplineRenderer;
import org.jfree.chart.title.CompositeTitle;
import org.jfree.chart.title.LegendTitle;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.Series;
import org.jfree.data.time.Day;
import org.jfree.data.time.Minute;
import org.jfree.data.time.Second;
import org.jfree.data.time.TimePeriodAnchor;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.DefaultHighLowDataset;
import org.jfree.data.xy.IntervalXYDataset;
import org.jfree.data.xy.OHLCDataset;
import org.jfree.data.xy.XYBarDataset;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.date.SerialDate;
import org.jfree.ui.ApplicationFrame;
import org.jfree.ui.RectangleEdge;
import org.jfree.ui.RectangleInsets;
import org.jfree.ui.RefineryUtilities;

/**
 * Overlaid XY plot with dual range axes.
 */
public class ChartObject{

    AttackModel model;
	
    public ChartObject(AttackModel model) {
    	this.model = model;
    }

    
    /*
     * Creates an overlaid chart
     * @return The chart.
     */
    public JFreeChart createOverlaidChart() {
    	    	
        // ----------------------------
        // Data and X-Y-Axis - Response Time Testprobes
    	// - Y-Achse 0
        final DateAxis yAxis = new DateAxis("Time");
        yAxis.setTickMarkPosition(DateTickMarkPosition.MIDDLE);
        // - X-Achse 0
        final NumberAxis xAxis0 = new NumberAxis("Response Time in ms");
        xAxis0.setStandardTickUnits(NumberAxis.createStandardTickUnits());
	//xAxis0.setTickUnit( new NumberTickUnit(1) );
        // - dataset
        // - renderer
        final XYDataset dataResponseTimeProbes = createDatasetResponseTime("testprobe");
        final XYLineAndShapeRenderer rendererResponseTimeProbes = new XYLineAndShapeRenderer(); // StandardXYItemRenderer(); -> should not be used
        rendererResponseTimeProbes.setSeriesPaint( 0, Color.blue );
	rendererResponseTimeProbes.setSeriesShape( 0, new Ellipse2D.Double(-1.5, -1.5, 3.0, 3.0) );
        rendererResponseTimeProbes.setSeriesLinesVisible(0, true);
        rendererResponseTimeProbes.setSeriesShapesVisible(0, true);
        rendererResponseTimeProbes.setUseOutlinePaint( false );
        rendererResponseTimeProbes.setSeriesOutlinePaint( 0, Color.black );
        rendererResponseTimeProbes.setUseFillPaint(true);
        rendererResponseTimeProbes.setSeriesFillPaint( 0, Color.blue );
           
        // ----------------------------
        // NEW XYPlot (new "Data and X-Y-Axis" from above added as default)
        final XYPlot plot = new XYPlot(dataResponseTimeProbes, yAxis, xAxis0, rendererResponseTimeProbes);
        
        // ----------------------------
        // Data and Axis 1 - Response time UNtampered             
        // - Dataset
        // - Renderer.
        // - Dataset zu X-Axis 0 mappen
        final XYDataset dataResponseTimeUntampered = createDatasetResponseTime("untampered");
        final XYLineAndShapeRenderer rendererResponseTimeUntampered = new XYLineAndShapeRenderer(); // StandardXYItemRenderer(); -> should not be used
        rendererResponseTimeUntampered.setSeriesPaint( 0, new Color(0,161,4));
        rendererResponseTimeUntampered.setSeriesShape( 0, new Ellipse2D.Double(-4, -4, 8.0, 8.0) );	
        rendererResponseTimeUntampered.setUseFillPaint(true);
        rendererResponseTimeUntampered.setSeriesFillPaint( 0, Color.white );
        rendererResponseTimeUntampered.setUseOutlinePaint( false );
        rendererResponseTimeUntampered.setSeriesOutlinePaint( 0, Color.black );	
        rendererResponseTimeUntampered.setSeriesToolTipGenerator( 0,
            new StandardXYToolTipGenerator(
                StandardXYToolTipGenerator.DEFAULT_TOOL_TIP_FORMAT,
                new SimpleDateFormat("d-MMM-yyyy"), new DecimalFormat("0.00")
            )
        );       
        plot.setDataset(2, dataResponseTimeUntampered);
        plot.setRenderer(2, rendererResponseTimeUntampered);
        //plot.mapDatasetToRangeAxis(0, 1);
        
        // ----------------------------
        // Data and Axis - Response time tampered
        // - Dataset
        // - Renderer
        // - Dataset zu X-Axis 2 mappen
        final XYDataset dataResponseTimeTampered = createDatasetResponseTime("tampered");
        XYLineAndShapeRenderer rendererResponseTimeTampered = new XYLineAndShapeRenderer(); //XYSplineRenderer();
        rendererResponseTimeTampered.setSeriesPaint(0, new Color(189,0,0));
        rendererResponseTimeTampered.setSeriesShape( 0, new Ellipse2D.Double(-4, -4, 8.0, 8.0) );//(-2.5, -2.5, 6.0, 6.0) );
        rendererResponseTimeTampered.setUseFillPaint(true);
        rendererResponseTimeTampered.setSeriesFillPaint( 0, Color.white );     
        rendererResponseTimeTampered.setUseOutlinePaint( false );
        rendererResponseTimeTampered.setSeriesOutlinePaint( 0, Color.black );
        plot.setDataset(3, dataResponseTimeTampered);
        plot.setRenderer(3, rendererResponseTimeTampered);
        //plot.mapDatasetToRangeAxis(0, 2);

        // ----------------------------
        // Data and X-Axis - Number Requests UNtampered
        // - X-Axis Number Requests 
        final NumberAxis xAxis1 = new NumberAxis("Number Requests Per Interval ("+(model.getIntervalLengthReport()/1000)+" sec)");
		xAxis1.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
		//xAxis1.setTickUnit( new NumberTickUnit(2) );
    	plot.setRangeAxis(1, xAxis1);
        // - Dataset
        // - Renderer
        final IntervalXYDataset dataNumberRequestsUntampered = createDatasetNumberRequestsUntampered();
        final XYBarRenderer rendererNumberRequestsUntampered = new XYBarRenderer(0.2);
        rendererNumberRequestsUntampered.setShadowVisible(false);
        rendererNumberRequestsUntampered.setBarPainter( new StandardXYBarPainter() );
        rendererNumberRequestsUntampered.setSeriesPaint(0, new Color(128,255,128));
        plot.setDataset(4, dataNumberRequestsUntampered);
        plot.setRenderer(4, rendererNumberRequestsUntampered);
        plot.mapDatasetToRangeAxis(4, 1);
        
        // -------------------------------
        // Data - Number Requests tampered
        // - Dataset
        // - Renderer
        final IntervalXYDataset dataNumberRequestsTampered = createDatasetNumberRequestsTampered();
        final XYBarRenderer rendererBarNumberRequestsTampered = new XYBarRenderer(0.2);
        rendererBarNumberRequestsTampered.setShadowVisible(false);
        rendererBarNumberRequestsTampered.setBarPainter( new StandardXYBarPainter() );
        rendererBarNumberRequestsTampered.setSeriesPaint(0, new Color(255,148,148));  
        plot.setDataset(5, dataNumberRequestsTampered);
        plot.setRenderer(5, rendererBarNumberRequestsTampered);
        plot.mapDatasetToRangeAxis(5, 1);
                
        // -------------------------
        // Other formating stuff
        // - add annotations
//        final double x = new Day(9, SerialDate.MARCH, 2002).getMiddleMillisecond();
//        final XYTextAnnotation annotation = new XYTextAnnotation("Anmerkung zu Datenpunkt", x, 1000.0);
//        annotation.setFont(new Font("SansSerif", Font.PLAIN, 9));
//        plot.addAnnotation(annotation);
        
        // -------------------------
        // Create custom LegendTitles
        // Legend Row 1
        LegendTitle legendL1 = new LegendTitle(plot.getRenderer(0)); 
        legendL1.setMargin(new RectangleInsets(2D, 2D, 2D, 2D)); 
        legendL1.setBorder( 0, 0, 0, 0 );
        LegendTitle legendR1 = new LegendTitle(plot.getRenderer(4)); 
        legendR1.setMargin(new RectangleInsets(2D, 2D, 2D, 2D)); 
        legendR1.setBorder( 0, 0, 0, 0 );       
        BlockContainer blockcontainer = new BlockContainer(new BorderArrangement()); 
        blockcontainer.setBorder( 0, 0, 0, 0 );
        blockcontainer.add(legendL1, RectangleEdge.LEFT); 
        blockcontainer.add(legendR1, RectangleEdge.RIGHT); 
        blockcontainer.add(new EmptyBlock(2000D, 0.0D)); 
        CompositeTitle compositetitle1 = new CompositeTitle(blockcontainer); 
        compositetitle1.setPosition( RectangleEdge.BOTTOM);        
        // Legend Row 2
        LegendTitle legendL2 = new LegendTitle(plot.getRenderer(2)); 
        legendL2.setMargin(new RectangleInsets(2D, 2D, 2D, 2D)); 
        legendL2.setBorder( 0, 0, 0, 0 );
        LegendTitle legendR2 = new LegendTitle(plot.getRenderer(5)); 
        legendR2.setMargin(new RectangleInsets(2D, 2D, 2D, 2D)); 
        legendR2.setBorder( 0, 0, 0, 0 );     
        BlockContainer blockcontainer2 = new BlockContainer(new BorderArrangement()); 
        blockcontainer2.setBorder( 0, 0, 0, 0 );
        blockcontainer2.add(legendL2, RectangleEdge.LEFT); 
        blockcontainer2.add(legendR2, RectangleEdge.RIGHT); 
        blockcontainer2.add(new EmptyBlock(2000D, 0.0D)); 
        CompositeTitle compositetitle2 = new CompositeTitle(blockcontainer2); 
        compositetitle2.setPosition( RectangleEdge.BOTTOM );
        // Legend Row 3
        LegendTitle legendL3 = new LegendTitle(plot.getRenderer(3)); 
        legendL3.setMargin(new RectangleInsets(2D, 2D, 2D, 2D)); 
        legendL3.setBorder( 0, 0, 0, 0 ); 
        BlockContainer blockcontainer3 = new BlockContainer(new BorderArrangement()); 
        blockcontainer3.setBorder( 0, 0, 0, 0 );
        blockcontainer3.add(legendL3, RectangleEdge.LEFT); 
        blockcontainer3.add(new EmptyBlock(2000D, 0.0D)); 
        CompositeTitle compositetitle3 = new CompositeTitle(blockcontainer3); 
        compositetitle3.setPosition( RectangleEdge.BOTTOM );        
        
        // -------------------------
        // create Chart
        // - return a new chart containing the overlaid plot...
        plot.setDatasetRenderingOrder(DatasetRenderingOrder.REVERSE);
        plot.setOrientation(PlotOrientation.VERTICAL);
        JFreeChart jFreeChart =  new JFreeChart(
                              model.getAttackName()+" - Response Time Plot",  // Roundtrip Time Plot
                              JFreeChart.DEFAULT_TITLE_FONT, 
                              plot, 
                              true
        );
        
        // Add new legend boxes + format
        jFreeChart.addSubtitle(compositetitle1);
        jFreeChart.addSubtitle(compositetitle2);
        jFreeChart.addSubtitle(compositetitle3);
        
        // Surpress old Legends
        LegendTitle legendee2 = jFreeChart.getLegend(0);
        legendee2.setVisible( false );
                
        return jFreeChart;
    }
    
    
    /*
     * Creates a Dataset with NumberRequestsUntampered
     *
     * @return The dataset.
     */
    private IntervalXYDataset createDatasetNumberRequestsUntampered() {

    	Date currentDate;
    	long currentMsTs;
    	final TimeSeries series = new TimeSeries("Sent Untampered Requests per Second"); 
	if(model.getMapLogEntryIntervalUntampered()!=null){
	    for (Map.Entry<Integer, LogEntryInterval> log : model.getMapLogEntryIntervalUntampered().entrySet()) { 
		    // Create TS from model.startTime and log.getIntervalNumber();
		    currentMsTs = model.getTsAttackStart() + log.getValue().getIntervalNumber();
		    currentDate = new Date(currentMsTs);
		    series.add(new Second(currentDate), (log.getValue().getNumberRequests()));
	    }
	}
    	
        final TimeSeriesCollection dataset = new TimeSeriesCollection(series);
        dataset.setXPosition(TimePeriodAnchor.MIDDLE);
                
        return dataset;
    }
    
    
    /*
     * Creates a Dataset with NumberRequestsTampered.
     *
     * @return The dataset.
     */
    private IntervalXYDataset createDatasetNumberRequestsTampered() {

    	Date currentDate;
    	long currentMsTs;
    	final TimeSeries series = new TimeSeries("Sent Tampered Requests per Second"); 	    	
	if(model.getMapLogEntryIntervalTampered()!=null){
	    for (Map.Entry<Integer, LogEntryInterval> log : model.getMapLogEntryIntervalTampered().entrySet()) { 
		    // Create TS from model.startTime and log.getIntervalNumber();
		    currentMsTs = model.getTsAttackStart() + log.getValue().getIntervalNumber();
		    currentDate = new Date(currentMsTs);
		    series.add(new Second(currentDate), (log.getValue().getNumberRequests()));
	    }    
	}
    	
        final TimeSeriesCollection dataset = new TimeSeriesCollection(series);
        dataset.setXPosition(TimePeriodAnchor.MIDDLE);
                
        return dataset;
    }        
    

    /*
     * Creates Dataset Response Time for following types: 
     * - tampered
     * - untampered
     * - testprobe
     * @param attackStartCal 
     * @return The dataset.
     */
    private synchronized XYDataset createDatasetResponseTime(String type) {

    	Map<Integer, LogEntryInterval> currentMap = null;
    	String name = null;
    	if(type.equals("tampered")){
    		currentMap = model.getMapLogEntryIntervalTampered();
    		name = "Mean Response Time Tampered Requests"; // Roundtrip Time
    	}else if (type.equals("untampered")){
    		currentMap = model.getMapLogEntryIntervalUntampered();
    		name = "Mean Response Time Untampered Requests"; // Roundtrip Time
    	}else if(type.equals("testprobe")){
    		currentMap = model.getMapLogEntryIntervalTestProbe();
    		name = "Mean Response Time Simulated 3rd Party Requests"; // Roundtrip Time
    	}else{
    		System.out.println("Invalid type");
    	}

	Date currentDate;
    	long currentMsTs;
    	final TimeSeries series = new TimeSeries(name); 	
	if(currentMap!=null){
	    for (Map.Entry<Integer, LogEntryInterval> log : currentMap.entrySet()) { 
		    // Create TS from model.startTime and log.getIntervalNumber();
		    currentMsTs = model.getTsAttackStart() + log.getValue().getIntervalNumber();
		    currentDate = new Date(currentMsTs);
		    //System.out.println(name+" Sekunde"+log.getValue().getIntervalNumber()+" TS: "+currentMsTs+" time "+log.getValue().getMeanResponseTime());
		    series.add(new Second(currentDate), (log.getValue().getMeanResponseTime()));
	    }   
	}
    	
        final TimeSeriesCollection dataset = new TimeSeriesCollection(series);
        dataset.setXPosition(TimePeriodAnchor.MIDDLE);
                
        return dataset;       
    }
}

     
