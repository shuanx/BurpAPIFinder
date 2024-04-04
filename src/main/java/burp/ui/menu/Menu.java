package burp.ui.menu;

import burp.*;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：被动扫描s
 */
public class Menu implements IContextMenuFactory {

    private BurpExtender burpExtender;

    public Menu(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        JMenuItem sendItem = new JMenuItem("doScan");
        // Override ActionListener
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] requestResponse = iContextMenuInvocation.getSelectedMessages();
            (new Thread(() -> {
//                this.burpExtender.stdout.println(requestResponse[0]);
            })).start();
        });
        menuItems.add(sendItem);
        return menuItems;
    }
}

