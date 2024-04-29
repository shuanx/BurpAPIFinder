package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class HeaderIconTypeRenderer extends DefaultTableCellRenderer {

    // 预加载图标
    private static final Icon FILTER_ICON = UiUtils.getImageIcon("/icon/filterIcon.png");

    public HeaderIconTypeRenderer() {
        super();
        setHorizontalAlignment(JLabel.CENTER); // 仅需设置一次
        setHorizontalTextPosition(JLabel.LEFT);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用super方法来保留原始行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 根据列设置图标
        if (column == 1) {
            setIcon(FILTER_ICON);
        } else {
            setIcon(null);
            setHorizontalAlignment(JLabel.LEADING); // 文本对齐方式恢复默认
        }

        // Since we're modifying the renderer itself, return 'this'
        return this;
    }
}
