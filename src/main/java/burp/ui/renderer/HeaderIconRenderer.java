package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class HeaderIconRenderer extends DefaultTableCellRenderer {
    // 预加载图标
    private static final Icon FILTER_ICON = UiUtils.getImageIcon("/icon/filterIcon.png", 17, 17);

    public HeaderIconRenderer() {
        super();
        setHorizontalAlignment(JLabel.CENTER); // 对所有单元格都适用
        setHorizontalTextPosition(JLabel.LEFT); // 将文本位置设置在图标左边
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); // 将手形光标应用于所有单元格
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // 调用super方法来保留原始行为
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // 如果是指定的类型列
        if (column == 6) {
            setIcon(FILTER_ICON);
        } else {
            setIcon(null);
        }

        // 由于我们修改了渲染器本身，返回 'this'
        return this;
    }
}
