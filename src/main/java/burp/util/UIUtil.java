package burp.util;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * @author ：metaStor
 * @date ：Created 2022/4/6 7:27 PM
 * @description: 获取垂直、水平panle
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
