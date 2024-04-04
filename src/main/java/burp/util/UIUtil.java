package burp.util;

import burp.BurpExtender;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：入口
 */
public class UIUtil {


    public static JPanel GetXPanel() {
        JPanel panel = new JPanel();
        panel.setAlignmentX(0.0f);
        panel.setBorder(new EmptyBorder(5, 0, 5, 0));
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        return panel;
    }

    public static JPanel GetYPanel() {
        JPanel panel = new JPanel();
        panel.setAlignmentX(0.0f);
        panel.setBorder(new EmptyBorder(5, 0, 5, 0));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        return panel;
    }
}
