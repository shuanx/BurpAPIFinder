package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * @author： shaun
 * @create： 2024/3/27 21:20
 * @description：TODO
 */
public class HeaderIconRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 保留原始行为
        Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 如果是类型列
        if (column == 6) {
            setIcon(UiUtils.getImageIcon("/icon/filterIcon.png", 17, 17));
            setHorizontalAlignment(JLabel.CENTER);
            setHorizontalTextPosition(JLabel.LEFT);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        } else {
            setIcon(null);
        }
        return comp;
    }
}