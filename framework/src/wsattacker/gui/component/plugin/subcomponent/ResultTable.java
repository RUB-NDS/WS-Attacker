/*
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2010  Christian Mainka
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package wsattacker.gui.component.plugin.subcomponent;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

import wsattacker.gui.util.CenteredTableCellRenderer;
import wsattacker.gui.util.ColoredResultTableCellRenderer;
import wsattacker.gui.util.MultiLineTableCellRenderer;
import wsattacker.main.composition.ResultObserver;
import wsattacker.main.plugin.result.Result;
import wsattacker.main.plugin.result.ResultEntry;
import wsattacker.main.plugin.result.ResultLevel;
import wsattacker.util.DateFormater;

public class ResultTable extends JTable {
	private static final long serialVersionUID = 1L;
	ResultTableModel model;
	
	public ResultTable() {
		model = new ResultTableModel();
		this.setModel(model);
		this.getColumnModel().getColumn(0).setPreferredWidth(50);
		this.getColumnModel().getColumn(1).setPreferredWidth(50);
		this.getColumnModel().getColumn(2).setPreferredWidth(100);
		this.getColumnModel().getColumn(3).setPreferredWidth(500);
		this.getColumnModel().getColumn(0).setCellRenderer(new CenteredTableCellRenderer());
		this.getColumnModel().getColumn(1).setCellRenderer(new ColoredResultTableCellRenderer());
		this.getColumnModel().getColumn(2).setCellRenderer(new CenteredTableCellRenderer());
		this.getColumnModel().getColumn(3).setCellRenderer(new MultiLineTableCellRenderer());
	}
	
	public void filterSources(List<String> sources) {
		model.filterSources(sources);
	}
	
	public void setLevel(ResultLevel level) {
		model.setLevel(level);
	}
	
	public class ResultTableModel extends AbstractTableModel implements ResultObserver {
		
		private static final long serialVersionUID = 1L;
		final private String[] columnNames = {"Time", "Level", "Source", "Content"};
		Result global;
		Result result;
		ResultLevel level;
		List<String> sources;
		
		public ResultTableModel() {
			result = new Result();
			global = Result.getGlobalResult();
			global.registerObserver(this);
			level = ResultLevel.Important;
			global.setObserverLevel(this, level);
			sources = new ArrayList<String>();
		}
		
		public void setLevel(ResultLevel level) {
			this.level = level;
			result = global.filterOnly(level);
			if(sources.size() > 0) {
				result = result.filterOnly(sources);
			}
			global.setObserverLevel(this, level);
			this.fireTableDataChanged();
		}
		
		public void filterSources(List<String> sources) {
			this.sources = sources;
			result = global.filterOnly(level);
			if(sources.size() > 0) {
				result = result.filterOnly(sources);
			}
			global.setSources(this, sources);
			this.fireTableDataChanged();
		}
		
		@Override
		public int getColumnCount() {
			return columnNames.length;
		}
		
		@Override
		public String getColumnName(int num){
			return this.columnNames[num];
		}
		
		@Override
		public boolean isCellEditable(int y, int x){
			return false;
		}

		@Override
		public int getRowCount() {
			return result.size();
		}

		@Override
		public Object getValueAt(int row, int col) {
			ResultEntry entry = result.get(row);
			switch (col) {
			case 0:
				return DateFormater.timeonly(entry.getDate());
			case 1:
				return entry.getLevel().toString();
			case 2:
				return entry.getSource();
			case 3:
				return entry.getContent();
			}
			return null;
		}
		
		@SuppressWarnings({ "rawtypes", "unchecked" })
		@Override
		public Class getColumnClass(int c) {
	        return getValueAt(0, c).getClass();
	    }

		@Override
		public void logUpdate(ResultEntry log) {
			result.add(log);
			this.fireTableDataChanged();
//			this.fireTableRowsInserted(getRowCount(), getRowCount()); // does not work for multiline cells
		}
		
		@Override
		public void logClear() {
			result.clear();
			this.fireTableRowsDeleted(0, getRowCount());
		}
		
	}

}
