package burp.ui.menu;

import burp.*;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author : metaStor
 * @date : Created 2022/4/30 5:24 PM
 * @description: 主动扫描Menu
 * @TODO: target中都没有记录，可在tabUI中查看扫描情况
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

            })).start();
        });
        menuItems.add(sendItem);
        return menuItems;
    }
}

