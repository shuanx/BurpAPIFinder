package burp.ui.renderer;

import burp.util.UiUtils;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

public class ButtonRenderer extends JPanel implements TableCellRenderer {
    private static final Icon EDIT_ICON = UiUtils.getImageIcon("/icon/editButton.png");
    private static final Icon DELETE_ICON = UiUtils.getImageIcon("/icon/deleteButton.png");

    private final JButton editButton;
    private final JButton deleteButton;

    public ButtonRenderer() {
        setLayout(new FlowLayout(FlowLayout.CENTER, 5, 0));
        editButton = createButton(EDIT_ICON);
        deleteButton = createButton(DELETE_ICON);

        add(editButton);
        add(deleteButton);
        setOpaque(true); // 设置为不透明，这样背景颜色变更才会生效
    }

    private JButton createButton(Icon icon) {
        JButton button = new JButton(icon);
        button.setPreferredSize(new Dimension(40, 20));
        button.setMargin(new Insets(0, 0, 0, 0)); // 设置按钮边距为0
        // 设置按钮边界为透明，以免在不同的LookAndFeel下显示不一致
        button.setBorder(BorderFactory.createEmptyBorder());
        button.setContentAreaFilled(false);
        return button;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        if (isSelected) {
            setBackground(table.getSelectionBackground());
        } else {
            setBackground(table.getBackground());
        }
        return this;
    }
}
