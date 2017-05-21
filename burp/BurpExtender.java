/*
Burp SniperScan Extension

MIT License
Copyright (c) 2017 Clément Notin / @cnotin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
	protected static IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
		callbacks = iBurpExtenderCallbacks;
		callbacks.setExtensionName("Sniper scan");
		callbacks.registerContextMenuFactory(this);
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuitems = new ArrayList<JMenuItem>();

		IHttpRequestResponse[] msgs = invocation.getSelectedMessages();
		// bounds of the currently selected text
		int[] bounds = invocation.getSelectionBounds();

		// only suggests to scan if a msg is selected and we have bounds (smthg
		// is selected)
		if (msgs != null && msgs.length >= 1 && bounds != null && bounds.length >= 2) {
			JMenuItem menu = new JMenuItem("Scan manual insertion point");
			menu.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					IHttpRequestResponse req = msgs[0];
					IHttpService service = req.getHttpService();

					// we just have one insertion point but the API requires a
					// List
					List<int[]> insertionPoints = new ArrayList<int[]>();
					insertionPoints.add(new int[] { bounds[0], bounds[1] });

					callbacks.doActiveScan(service.getHost(), service.getPort(), (service.getProtocol() == "https"),
							req.getRequest(), insertionPoints);
				}
			});
			menuitems.add(menu);
		}
		return menuitems;
	}
}