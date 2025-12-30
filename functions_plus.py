"""
Functions+ IDA Pro plugin -- alternative version of functions window.

Splits functions names and groups by namespaces.
Includes sorting and searching functionality.

"""

import re
import csv
from collections import OrderedDict

import ida_funcs
import ida_ida
import ida_name
import idaapi
import idc
import idautils

from idaapi import PluginForm

# Try PySide6 first (IDA 9.x), fall back to PyQt5
try:
    from PySide6 import QtWidgets, QtGui, QtCore
    USING_PYSIDE6 = True
except ImportError:
    from PyQt5 import QtWidgets, QtGui, QtCore
    USING_PYSIDE6 = False

__author__ = "r00tz, xxxzsx, Arthur Gerkis (optimized)"
__version__ = "2.1"


class FunctionData:
    """Holds data of the function. Uses __slots__ for memory efficiency."""
    __slots__ = ["args", "flags", "addr"]

    def __init__(self, addr, flags, args=""):
        self.args = args
        self.flags = flags
        self.addr = addr


class Cols:
    """Handles column definitions and data retrieval."""

    NAMES = ["Name", "Address", "Segment", "Length", "Locals", "Arguments"]
    EXTRA_NAMES = ["R", "F", "L", "S", "B", "T", "="]

    def __init__(self, show_extra_fields=False):
        self.show_extra_fields = show_extra_fields
        self.names = self.NAMES.copy()
        if show_extra_fields:
            self.names.extend(self.EXTRA_NAMES)

    def get_row_data(self, addr, flags):
        """Get all column data for a function in one call."""
        func_end = idc.get_func_attr(addr, idc.FUNCATTR_END)

        data = [
            None,  # Name is set separately
            "{:08X}".format(addr),
            idc.get_segm_name(addr),
            "{:08X}".format(func_end - addr) if func_end != idc.BADADDR else "00000000",
            "{:08X}".format(idc.get_func_attr(addr, idc.FUNCATTR_FRSIZE)),
            "{:08X}".format(idc.get_func_attr(addr, idc.FUNCATTR_ARGSIZE)),
        ]

        if self.show_extra_fields:
            data.extend([
                "R" if not flags & idc.FUNC_NORET else ".",
                "F" if flags & idc.FUNC_FAR else ".",
                "L" if flags & idc.FUNC_LIB else ".",
                "S" if flags & idc.FUNC_STATIC else ".",
                "B" if flags & idc.FUNC_FRAME else ".",
                "T" if idc.get_type(addr) else ".",
                "=" if flags & idc.FUNC_BOTTOMBP else ".",
            ])

        return data


class FunctionsTree:
    """Builds tree of functions with all relevant information."""

    def __init__(self):
        self._chunks_regexp = re.compile(r"(.*?)(?:|\((.*?)\))$")

    def get(self):
        """Returns functions tree."""
        functions_list = self._get_list_of_functions()
        return self._build_functions_tree(functions_list)

    @staticmethod
    def _get_list_of_functions():
        """Gets all functions as a list of tuples (name, addr, flags)."""
        functions_list = []

        for func_ea in idautils.Functions():
            function_name = ida_funcs.get_func_name(func_ea)
            if function_name:
                flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
                functions_list.append((function_name, func_ea, flags))

        # Sort by name (case-insensitive)
        functions_list.sort(key=lambda x: x[0].lower())
        return functions_list

    def _build_functions_tree(self, functions_list):
        """Builds tree of functions."""
        functions_tree = OrderedDict()

        for function_name, addr, flags in functions_list:
            demangled_name = self._maybe_demangle(function_name)
            args, chunks = self._get_chunks(demangled_name)
            self._add_to_tree(chunks, functions_tree, FunctionData(addr, flags, args))

        return functions_tree

    def _add_to_tree(self, chunks, tree, func_data):
        """Adds function to the tree structure."""
        if not chunks:
            return

        name = chunks[0]
        if not name:
            return

        if len(chunks) == 1:
            tree[name + func_data.args] = func_data
            return

        if name not in tree:
            tree[name] = OrderedDict()

        if isinstance(tree[name], OrderedDict):
            self._add_to_tree(chunks[1:], tree[name], func_data)

    def _get_chunks(self, func_string):
        """Splits function name by namespaces."""
        matches = re.match(self._chunks_regexp, func_string)
        if not matches:
            return "", []

        args = "({})".format(matches.group(2)) if matches.group(2) else ""

        main_part = matches.group(1)
        if not main_part:
            return args, []

        if main_part[0] == "`":
            return args, [main_part]

        # Parse namespaces, respecting template brackets
        chunks = []
        open_brackets = 0
        current = []

        for char in main_part:
            if char == "<":
                open_brackets += 1
                current.append(char)
            elif char == ">":
                open_brackets -= 1
                current.append(char)
            elif char == ":" and open_brackets == 0:
                if current:
                    chunks.append("".join(current))
                current = []
            else:
                current.append(char)

        if current:
            chunks.append("".join(current))

        return args, chunks

    @staticmethod
    def _maybe_demangle(function_name):
        """Demangles name if required."""
        if "@" not in function_name:
            return function_name

        try:
            mask = ida_ida.inf_get_short_demnames()
        except AttributeError:
            mask = idc.get_inf_attr(idc.INF_SHORT_DN)

        demangled = ida_name.demangle_name(function_name, mask, ida_name.DQT_FULL)
        return demangled if demangled else function_name


def _count_functions(tree_data):
    """Count total functions in a tree branch."""
    if isinstance(tree_data, FunctionData):
        return 1

    count = 0
    for data in tree_data.values():
        count += _count_functions(data)
    return count


class FunctionsPlus(PluginForm):
    """Functions+ plugin"""

    # Colors for different function types (good contrast for all themes)
    COLORS = {
        "thunk_bg": QtGui.QColor("#E8DAEF"),
        "thunk_fg": QtGui.QColor("#000000"),
        "lib_bg": QtGui.QColor("#D1F2EB"),
        "lib_fg": QtGui.QColor("#000000"),
    }

    def __init__(self):
        super(FunctionsPlus, self).__init__()
        self._tree = None
        self._show_extra_fields = False
        self._cols = Cols(self._show_extra_fields)
        self._search_bar = None
        self._parent = None
        self._search_timer = None
        self._tree_data = None
        self._status_label = None
        self._is_populating = False

    def OnCreate(self, form):
        """Called when the plugin form is created."""
        self._parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)

        # Search bar with delayed filtering
        search_layout = QtWidgets.QHBoxLayout()
        search_layout.setSpacing(2)

        self._search_bar = QtWidgets.QLineEdit()
        self._search_bar.setPlaceholderText("Search functions... (Enter to search)")
        self._search_bar.returnPressed.connect(self._do_filter)
        search_layout.addWidget(self._search_bar)

        clear_btn = QtWidgets.QPushButton("Clear")
        clear_btn.setFixedWidth(50)
        clear_btn.clicked.connect(self._clear_search)
        search_layout.addWidget(clear_btn)

        layout.addLayout(search_layout)

        # Create tree widget with optimized settings
        self._tree = QtWidgets.QTreeWidget()
        self._tree.setColumnCount(len(self._cols.names))
        self._tree.setHeaderLabels(self._cols.names)
        self._tree.itemDoubleClicked.connect(self._on_dblclick)
        self._tree.itemExpanded.connect(self._on_item_expanded)
        self._tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)

        # Performance optimizations
        self._tree.setUniformRowHeights(True)  # Major performance boost
        self._tree.setAnimated(False)  # Disable animations - prevents shaking
        self._tree.setAutoScroll(False)  # Disable auto-scroll during updates
        self._tree.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self._tree.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)

        # Disable alternating colors - causes visibility issues in dark themes
        self._tree.setAlternatingRowColors(False)

        # Header settings - disable sort indicator to prevent header resize/shake
        header = self._tree.header()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(False)  # Prevents header shake
        header.sectionClicked.connect(self._on_header_clicked)
        header.setStretchLastSection(True)

        layout.addWidget(self._tree)

        # Status bar
        self._status_label = QtWidgets.QLabel("Loading...")
        self._status_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self._status_label)

        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.setSpacing(4)

        refresh_btn = QtWidgets.QPushButton("Refresh")
        refresh_btn.clicked.connect(self._populate_tree)
        btn_layout.addWidget(refresh_btn)

        expand_btn = QtWidgets.QPushButton("Expand All")
        expand_btn.clicked.connect(self._expand_all)
        btn_layout.addWidget(expand_btn)

        collapse_btn = QtWidgets.QPushButton("Collapse All")
        collapse_btn.clicked.connect(self._tree.collapseAll)
        btn_layout.addWidget(collapse_btn)

        export_btn = QtWidgets.QPushButton("Export CSV")
        export_btn.clicked.connect(self._export_to_csv)
        btn_layout.addWidget(export_btn)

        layout.addLayout(btn_layout)

        # Setup search timer for delayed filtering (only on text change, not enter)
        self._search_timer = QtCore.QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._do_filter)

        # Connect text changed with delay
        self._search_bar.textChanged.connect(self._on_search_changed)

        self._parent.setLayout(layout)

        # Set column widths before populating
        self._tree.setColumnWidth(0, 400)
        self._tree.setColumnWidth(1, 80)
        self._tree.setColumnWidth(2, 50)
        for i in range(3, 6):
            self._tree.setColumnWidth(i, 70)

        # Populate tree
        self._populate_tree()

    def OnClose(self, form):
        """Called when the plugin form is closed."""
        if self._search_timer:
            self._search_timer.stop()

    def Show(self):
        """Creates the form if not created or focuses it if it was."""
        return PluginForm.Show(self, "Functions+")

    def _populate_tree(self):
        """Populates functions tree with full update blocking."""
        if self._is_populating:
            return

        self._is_populating = True
        self._status_label.setText("Loading...")

        # Block all signals and updates during population
        self._tree.blockSignals(True)
        self._tree.setUpdatesEnabled(False)

        try:
            self._tree.clear()
            self._tree_data = FunctionsTree().get()
            self._build_tree_items(self._tree, self._tree_data)

            # Count total functions
            total = _count_functions(self._tree_data)
            namespaces = len(self._tree_data)
            self._status_label.setText(
                "Total: {} functions in {} namespaces".format(total, namespaces)
            )
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.blockSignals(False)
            self._is_populating = False

    def _build_tree_items(self, parent, tree_data, depth=0):
        """Build tree items from tree data structure."""
        if not tree_data:
            return

        items_to_add = []

        for name, data in sorted(tree_data.items()):
            if isinstance(data, FunctionData):
                # Leaf node - actual function
                item = QtWidgets.QTreeWidgetItem()
                item.setText(0, name)
                item.setData(0, QtCore.Qt.UserRole, data)  # Store function data

                # Get all column data at once
                row_data = self._cols.get_row_data(data.addr, data.flags)
                for col_idx, col_data in enumerate(row_data):
                    if col_idx > 0 and col_data:
                        item.setText(col_idx, col_data)

                # Apply colors based on function type
                if data.flags & idc.FUNC_THUNK:
                    self._apply_row_colors(item, "thunk_bg", "thunk_fg")
                elif data.flags & idc.FUNC_LIB:
                    self._apply_row_colors(item, "lib_bg", "lib_fg")

                items_to_add.append(item)
            else:
                # Namespace node
                child_count = _count_functions(data)
                display_name = "{} ({} {})".format(
                    name, child_count, "item" if child_count == 1 else "items"
                )

                item = QtWidgets.QTreeWidgetItem()
                item.setText(0, display_name)
                item.setData(0, QtCore.Qt.UserRole + 1, data)  # Store for lazy load
                item.setData(0, QtCore.Qt.UserRole + 2, False)  # Not loaded yet

                font = QtGui.QFont()
                font.setBold(True)
                item.setFont(0, font)

                # Add placeholder child to show expand arrow
                placeholder = QtWidgets.QTreeWidgetItem(item)
                placeholder.setText(0, "Loading...")

                items_to_add.append(item)

        # Add all items at once (more efficient)
        if isinstance(parent, QtWidgets.QTreeWidget):
            parent.addTopLevelItems(items_to_add)
        else:
            parent.addChildren(items_to_add)

    def _apply_row_colors(self, item, bg_key, fg_key):
        """Apply background and foreground colors to all columns."""
        bg_color = self.COLORS[bg_key]
        fg_color = self.COLORS[fg_key]
        for col_idx in range(len(self._cols.names)):
            item.setBackground(col_idx, bg_color)
            item.setForeground(col_idx, fg_color)

    def _on_item_expanded(self, item):
        """Handle item expansion - lazy load children."""
        if self._is_populating:
            return

        # Check if this item needs lazy loading
        is_loaded = item.data(0, QtCore.Qt.UserRole + 2)
        if is_loaded:
            return

        tree_data = item.data(0, QtCore.Qt.UserRole + 1)
        if not tree_data:
            return

        # Mark as loaded
        item.setData(0, QtCore.Qt.UserRole + 2, True)

        # Block signals during update
        self._tree.blockSignals(True)
        self._tree.setUpdatesEnabled(False)

        try:
            # Remove placeholder
            while item.childCount() > 0:
                item.removeChild(item.child(0))

            # Add actual children
            self._build_tree_items(item, tree_data, depth=1)
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.blockSignals(False)

    def _on_header_clicked(self, logical_index):
        """Handle column header click for sorting."""
        current_order = self._tree.header().sortIndicatorOrder()

        # Toggle sort order
        if self._tree.sortColumn() == logical_index:
            new_order = (
                QtCore.Qt.DescendingOrder
                if current_order == QtCore.Qt.AscendingOrder
                else QtCore.Qt.AscendingOrder
            )
        else:
            new_order = QtCore.Qt.AscendingOrder

        self._tree.sortByColumn(logical_index, new_order)

    def _on_dblclick(self, item):
        """Handles double click event - jump to function."""
        addr_text = item.text(1)
        if addr_text:
            try:
                idaapi.jumpto(int(addr_text, 16))
            except ValueError:
                pass

    def _on_search_changed(self, text):
        """Called when search text changes - starts delayed filter."""
        if self._search_timer:
            self._search_timer.stop()
            self._search_timer.start(500)  # 500ms delay

    def _clear_search(self):
        """Clear search and show all items."""
        self._search_bar.clear()
        self._show_all_items()

    def _do_filter(self):
        """Perform the filtering."""
        if self._search_timer:
            self._search_timer.stop()

        search_text = self._search_bar.text().strip().lower()

        if not search_text:
            self._show_all_items()
            return

        self._tree.blockSignals(True)
        self._tree.setUpdatesEnabled(False)

        try:
            visible_count = 0
            for i in range(self._tree.topLevelItemCount()):
                item = self._tree.topLevelItem(i)
                if self._filter_item(item, search_text):
                    visible_count += self._count_visible_leaves(item)

            self._status_label.setText("Found: {} matching functions".format(visible_count))
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.blockSignals(False)

    def _filter_item(self, item, search_text):
        """Recursively filter items in the tree."""
        # Ensure children are loaded for searching
        is_loaded = item.data(0, QtCore.Qt.UserRole + 2)
        if is_loaded is False:  # Explicitly False means not loaded
            tree_data = item.data(0, QtCore.Qt.UserRole + 1)
            if tree_data:
                item.setData(0, QtCore.Qt.UserRole + 2, True)
                while item.childCount() > 0:
                    item.removeChild(item.child(0))
                self._build_tree_items(item, tree_data, depth=1)

        # Check this item's name
        item_matches = search_text in item.text(0).lower()

        # Check children
        child_visible = False
        for i in range(item.childCount()):
            child = item.child(i)
            if self._filter_item(child, search_text):
                child_visible = True

        should_show = item_matches or child_visible
        item.setHidden(not should_show)

        # Auto-expand if children match
        if child_visible:
            item.setExpanded(True)

        return should_show

    def _show_all_items(self):
        """Show all items (clear filter)."""
        self._tree.blockSignals(True)
        self._tree.setUpdatesEnabled(False)

        try:
            self._show_item_recursive(self._tree.invisibleRootItem())

            total = _count_functions(self._tree_data) if self._tree_data else 0
            namespaces = len(self._tree_data) if self._tree_data else 0
            self._status_label.setText(
                "Total: {} functions in {} namespaces".format(total, namespaces)
            )
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.blockSignals(False)

    def _show_item_recursive(self, item):
        """Recursively show all items."""
        item.setHidden(False)
        for i in range(item.childCount()):
            self._show_item_recursive(item.child(i))

    def _count_visible_leaves(self, item):
        """Count visible leaf items."""
        if item.isHidden():
            return 0

        if item.childCount() == 0:
            return 1

        count = 0
        for i in range(item.childCount()):
            count += self._count_visible_leaves(item.child(i))
        return count

    def _expand_all(self):
        """Expand all items (loads all lazy items)."""
        self._tree.blockSignals(True)
        self._tree.setUpdatesEnabled(False)

        try:
            self._expand_recursive(self._tree.invisibleRootItem())
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.blockSignals(False)

    def _expand_recursive(self, item):
        """Recursively expand and load all items."""
        # Trigger lazy loading if needed
        is_loaded = item.data(0, QtCore.Qt.UserRole + 2)
        if is_loaded is False:
            tree_data = item.data(0, QtCore.Qt.UserRole + 1)
            if tree_data:
                item.setData(0, QtCore.Qt.UserRole + 2, True)
                while item.childCount() > 0:
                    item.removeChild(item.child(0))
                self._build_tree_items(item, tree_data, depth=1)

        item.setExpanded(True)

        for i in range(item.childCount()):
            child = item.child(i)
            if child.childCount() > 0 or child.data(0, QtCore.Qt.UserRole + 1):
                self._expand_recursive(child)

    def _show_context_menu(self, position):
        """Show context menu for the selected item."""
        item = self._tree.itemAt(position)
        if item is None or item.childCount() > 0:
            return

        # Only show for leaf items (actual functions)
        if item.data(0, QtCore.Qt.UserRole + 1) is not None:
            return

        menu = QtWidgets.QMenu()
        rename_action = menu.addAction("Rename Function")
        set_bp_action = menu.addAction("Set Breakpoint")
        add_cmt_action = menu.addAction("Add Comment")
        menu.addSeparator()
        copy_name_action = menu.addAction("Copy Name")
        copy_addr_action = menu.addAction("Copy Address")

        action = menu.exec_(self._tree.viewport().mapToGlobal(position))

        addr = self._get_item_address(item)
        if addr is None:
            return

        if action == rename_action:
            self._rename_function(item, addr)
        elif action == set_bp_action:
            idc.add_bpt(addr)
        elif action == add_cmt_action:
            self._add_comment(addr)
        elif action == copy_name_action:
            QtWidgets.QApplication.clipboard().setText(item.text(0))
        elif action == copy_addr_action:
            QtWidgets.QApplication.clipboard().setText(item.text(1))

    def _get_item_address(self, item):
        """Get address from item, return None if invalid."""
        addr_text = item.text(1)
        if not addr_text:
            return None
        try:
            return int(addr_text, 16)
        except ValueError:
            return None

    def _rename_function(self, item, addr):
        """Rename the selected function."""
        old_name = item.text(0)
        new_name, ok = QtWidgets.QInputDialog.getText(
            self._parent, "Rename Function", "New function name:", text=old_name
        )
        if ok and new_name:
            idc.set_name(addr, new_name)
            item.setText(0, new_name)

    def _add_comment(self, addr):
        """Add a comment to the selected function."""
        comment, ok = QtWidgets.QInputDialog.getText(
            self._parent, "Add Comment", "Enter comment:"
        )
        if ok and comment:
            idc.set_cmt(addr, comment, 0)

    def _export_to_csv(self):
        """Export the function list to a CSV file."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self._parent, "Save CSV", "", "CSV Files (*.csv)"
        )

        if not filename:
            return

        # Expand all to ensure complete export
        self._expand_all()
        self._tree.collapseAll()

        try:
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(self._cols.names)
                self._write_tree_to_csv(self._tree.invisibleRootItem(), writer)

            self._status_label.setText("Exported to {}".format(filename))
        except Exception as e:
            self._status_label.setText("Export error: {}".format(e))

    def _write_tree_to_csv(self, item, writer):
        """Recursively write tree items to CSV."""
        for i in range(item.childCount()):
            child = item.child(i)
            if child.childCount() == 0:
                row = [child.text(j) for j in range(self._tree.columnCount())]
                writer.writerow(row)
            else:
                self._write_tree_to_csv(child, writer)


class FunctionsPlusPlugin(idaapi.plugin_t):
    """IDA Plugin wrapper for Functions+."""

    flags = idaapi.PLUGIN_KEEP
    comment = "Functions+"
    help = "Enhanced functions window with search"
    wanted_name = "Functions+"
    wanted_hotkey = "Ctrl+Shift+F"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        funp = FunctionsPlus()
        funp.Show()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return FunctionsPlusPlugin()


if __name__ == "__main__":
    funp = FunctionsPlus()
    funp.Show()