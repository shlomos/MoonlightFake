package org.moonlightcontroller.samples.actions;

public class ActionLog implements Action {

	private String message;
	
	private ActionLog(String message) {
		this.message = message;
	}
	
	public String getType() {
		return "Log";
	}
	
	public String getMessage() {
		return this.message;
	}
	
	public static class Builder implements Action.Builder {

		private String message;
		
		public Builder() {
			
		}
		
		public Builder(String message) {
			this.message = message;
		}
		
		@Override
		public Action build() {
			return new ActionLog(message);
		}
		
	}
}
