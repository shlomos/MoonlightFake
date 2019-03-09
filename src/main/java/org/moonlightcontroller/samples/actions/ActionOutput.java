package org.moonlightcontroller.samples.actions;


public class ActionOutput implements Action {
	
	private String iface;
	
	private ActionOutput(String iface) {
		this.iface = iface;
	}
	
	public String getType() {
		return "Output";
	}
	
	public String getInterface() {
		return iface;
	}
	
	public static class Builder implements Action.Builder {

		private String iface;
		
		public Builder() {
			
		}
		
		public Builder(String iface) {
			this.iface = iface;
		}

		public Builder setInterface(String iface) {
			this.iface = iface;
			return this;
		}
		
		@Override
		public Action build() {
			return new ActionOutput(iface);
		}
		
	}
}
