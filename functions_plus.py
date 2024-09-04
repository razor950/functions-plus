"""
Functions+ IDA Pro plugin -- alternative version of functions window.

Splits functions names and groups by namespaces.
Includes sorting and searching functionality.
"""

import re
import csv
import json
from collections import OrderedDict

import idaapi
import idc
import idautils

from idaapi import PluginForm
from PyQt5 import QtWidgets, QtGui, QtCore

__author__ = 'r00tz, xxxzsx, Arthur Gerkis'
__version__ = '1.2'


class FunctionState:
    """Holds the state of the current function."""

    def __init__(self):
        self.args = ''
        self.flags = 0
        self.addr = 0


class FunctionData:
    """Holds data of the function."""

    def __init__(self, state):
        self.args = state.args
        self.flags = state.flags
        self.addr = state.addr


class Cols:
    """Class which is responsible for handling columns."""

    def __init__(self, show_extra_fields):
        self.addr = None
        self.flags = None
        self.show_extra_fields = show_extra_fields
        self.names = [
            'Name', 'Address', 'Segment', 'Length', 'Locals', 'Arguments'
        ]

        self.handlers = {
            0: lambda: None,
            1: lambda: self.fmt(self.addr),
            2: lambda: f'{idc.get_segm_name(self.addr)}',
            3: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_END) - self.addr),
            4: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_FRSIZE)),
            5: lambda: self.fmt(idc.get_func_attr(self.addr, idc.FUNCATTR_ARGSIZE))
        }

        if self.show_extra_fields:
            self.names.extend(['R', 'F', 'L', 'S', 'B', 'T', '='])
            self.handlers.update({
                6:  lambda: self.is_true(not self.flags & idc.FUNC_NORET, 'R'),
                7:  lambda: self.is_true(self.flags & idc.FUNC_FAR, 'F'),
                8:  lambda: self.is_true(self.flags & idc.FUNC_LIB, 'L'),
                9:  lambda: self.is_true(self.flags & idc.FUNC_STATIC, 'S'),
                10: lambda: self.is_true(self.flags & idc.FUNC_FRAME, 'B'),
                11: lambda: self.is_true(idc.get_type(self.addr), 'T'),
                12: lambda: self.is_true(self.flags & idc.FUNC_BOTTOMBP, '=')
            })

    def set_data(self, addr, flags):
        """Sets data actual for the current function."""
        self.addr = addr
        self.flags = flags

    def item(self, index):
        """Gets the data according to requested col index."""
        return self.handlers[index]()

    @staticmethod
    def is_true(flag, char):
        """Wrapper to conform IDA default UI view."""
        return char if flag else '.'

    @staticmethod
    def fmt(value):
        """Wrapper to conform IDA default UI view."""
        return f'{value:08X}'


class FunctionsTree:
    """Builds tree of functions with all relevant information."""

    def __init__(self):
        self.chunks_regexp = re.compile(r'(.*?)(?:|\((.*?)\))$')
        self.simple_regexp = re.compile(r'^[a-zA-Z0-9_]*$')

    def get(self):
        """Returns functions tree."""
        functions_list = self.get_list_of_functions()
        return self.build_functions_tree(functions_list)

    @staticmethod
    def get_list_of_functions():
        """Gets all functions list."""
        functions_list = {}
        seg_ea = idc.get_segm_by_sel(idc.SEG_NORM)

        for func_ea in idautils.Functions(idc.get_segm_start(seg_ea),
                                          idc.get_segm_end(seg_ea)):
            function_name = idc.get_func_name(func_ea)
            functions_list[function_name] = func_ea

        return functions_list

    def build_functions_tree(self, functions_list):
        """Builds tree of functions."""
        func_state = FunctionState()
        functions_tree = OrderedDict()

        for function_name in sorted(functions_list):
            func_state.args = ''
            func_state.addr = functions_list[function_name]
            func_state.flags = \
                idc.get_func_attr(func_state.addr, idc.FUNCATTR_FLAGS)
            demangled_name = self.maybe_demangle(function_name)
            chunks = self.get_chunks(demangled_name, func_state)
            self.maybe_push(chunks, functions_tree, func_state)

        return functions_tree

    def maybe_push(self, chunks, functions_tree, func_state):
        """Adds new function name or properties to the tree."""
        if isinstance(functions_tree, FunctionData):
            return

        name = chunks.pop(0)
        if not name:
            return

        if not chunks:
            functions_tree[name + func_state.args] = FunctionData(func_state)
            return

        if name not in functions_tree:
            functions_tree[name] = OrderedDict()

        self.maybe_push(chunks, functions_tree[name], func_state)

    def get_chunks(self, func_string, func_state):
        """Splits function name by namespaces."""
        new_chunks = []
        matches = re.match(self.chunks_regexp, func_string)
        if not matches:
            return []

        args = ''
        if matches.group(2):
            args = f'({matches.group(2)})'
        func_state.args = args

        chunks = list(matches.group(1))
        if chunks[0] == '`':
            return [matches.group(1)]

        open_left_tpl = 0
        tmp_chunk = ''
        for chunk in chunks:
            if chunk == ':' and open_left_tpl == 0:
                if tmp_chunk:
                    new_chunks.append(tmp_chunk)
                tmp_chunk = ''
                continue
            if chunk == '<':
                open_left_tpl += 1
            if chunk == '>':
                open_left_tpl -= 1
            tmp_chunk += chunk
        new_chunks.append(tmp_chunk)
        return new_chunks

    def maybe_demangle(self, function_name):
        """Demangles name if required."""
        if '@' in function_name:
            function_name = self.demangle(function_name)
        return function_name

    @staticmethod
    def demangle(name):
        """Demangles name."""
        mask = idc.get_inf_attr(idc.INF_SHORT_DN)
        demangled = idc.demangle_name(name, mask)
        return demangled if demangled is not None else name


class FunctionsPlus(PluginForm):
    """Functions+ plugin."""

    def __init__(self):
        super(FunctionsPlus, self).__init__()
        if idc.get_inf_attr(idc.INF_PROCNAME).lower() != 'metapc':
            print('Functions+ warning: not tested in this configuration')
        self.tree = None
        self.icon = 135
        self.show_extra_fields = False
        self.cols = Cols(self.show_extra_fields)
        self.search_bar = None
        self.sort_combo = None

    def OnCreate(self, form):
        """Called when the plugin form is created."""
        parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()

        # Add search bar
        self.search_bar = QtWidgets.QLineEdit()
        self.search_bar.setPlaceholderText("Search functions...")
        self.search_bar.textChanged.connect(self.filter_functions)
        layout.addWidget(self.search_bar)

        # Add sort combo box
        self.sort_combo = QtWidgets.QComboBox()
        self.sort_combo.addItems(["Name", "Address", "Segment", "Length", "Locals", "Arguments"])
        self.sort_combo.currentIndexChanged.connect(self.sort_functions)
        layout.addWidget(self.sort_combo)

        # Create tree widget
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(self.cols.names))
        self.tree.setHeaderLabels(self.cols.names)
        self.tree.itemDoubleClicked.connect(self._dblclick)
        layout.addWidget(self.tree)

        self._populate_tree()

        self.tree.setColumnWidth(0, 512)
        for index in range(6, len(self.cols.names)):
            self.tree.setColumnWidth(index, 32)
        self.tree.setAlternatingRowColors(True)

        parent.setLayout(layout)

    def _populate_tree(self):
        """Populates functions tree."""
        self.tree.clear()
        self._build_tree(FunctionsTree().get(), self.tree)

    def _build_tree(self, function_tree, root):
        """Builds Qt Widget tree."""
        if not function_tree:
            return

        if isinstance(function_tree, FunctionData):
            self._handle_function_data_instance(function_tree, root)
            return

        for name, tree in sorted(function_tree.items()):
            func_item = QtWidgets.QTreeWidgetItem(root)
            if not isinstance(tree, FunctionData):
                name = self._handle_class_name(tree, name, func_item)
            func_item.setText(0, name)
            self._build_tree(tree, func_item)

    def _handle_class_name(self, tree, name, func_item):
        """Handles class name."""
        tree_keys_len = len(list(tree.keys()))
        name = f'{name} ({tree_keys_len} {self._get_word(tree_keys_len)})'
        font = QtGui.QFont()
        font.setBold(True)
        func_item.setFont(0, font)
        return name

    def _handle_function_data_instance(self, function_tree, root):
        """Handles FunctionData instance."""
        flags = int(function_tree.flags)
        addr = function_tree.addr

        self.cols.set_data(addr, flags)

        for index in range(len(self.cols.names)):
            if index > 0:
                root.setText(index, self.cols.item(index))
            if flags & idc.FUNC_THUNK:
                root.setBackground(index, QtGui.QColor('#E8DAEF'))
            if flags & idc.FUNC_LIB:
                root.setBackground(index, QtGui.QColor('#D1F2EB'))

    @staticmethod
    def _get_word(len):
        """Gets proper word for number."""
        return "item" if len % 10 == 1 and len % 100 != 11 else "items"

    def _dblclick(self, item):
        """Handles double click event."""
        try:
            idaapi.jumpto(int(item.text(1), 16))
        except ValueError:
            pass

    def filter_functions(self):
        """Filters functions based on search text."""
        search_text = self.search_bar.text().lower()
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i), search_text)

    def _filter_item(self, item, search_text):
        """Recursively filters items in the tree."""
        should_show = search_text in item.text(0).lower()
        
        for i in range(item.childCount()):
            child_visible = self._filter_item(item.child(i), search_text)
            should_show = should_show or child_visible

        item.setHidden(not should_show)
        return should_show

    def sort_functions(self):
        """Sorts functions based on selected criterion."""
        column = self.sort_combo.currentIndex()
        self.tree.sortItems(column, QtCore.Qt.AscendingOrder)

    def OnClose(self, form):
        """Called when the plugin form is closed."""
        pass

    def Show(self):
        """Creates the form if not created or focuses it if it was."""
        return PluginForm.Show(self, 'Functions+')

class SortableTreeWidget(QtWidgets.QTreeWidget):
    """Custom QTreeWidget with sortable columns and additional features."""

    def __init__(self, parent=None):
        super(SortableTreeWidget, self).__init__(parent)
        self.header().setSectionsClickable(True)
        self.header().sectionClicked.connect(self.handle_section_clicked)
        self.current_sort_column = 0
        self.current_sort_order = QtCore.Qt.AscendingOrder
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.update_header_texts()

    def handle_section_clicked(self, logical_index):
        """Handle column header click events."""
        if self.current_sort_column == logical_index:
            self.current_sort_order = QtCore.Qt.DescendingOrder if self.current_sort_order == QtCore.Qt.AscendingOrder else QtCore.Qt.AscendingOrder
        else:
            self.current_sort_column = logical_index
            self.current_sort_order = QtCore.Qt.AscendingOrder

        self.sortItems(self.current_sort_column, self.current_sort_order)
        self.update_header_texts()

    def update_header_texts(self):
        """Update header texts to show sort direction."""
        header = self.header()
        for i in range(header.count()):
            current_text = header.model().headerData(i, QtCore.Qt.Horizontal, QtCore.Qt.DisplayRole)
            if i == self.current_sort_column:
                arrow = " ▲" if self.current_sort_order == QtCore.Qt.AscendingOrder else " ▼"
                new_text = f"{current_text.split(' ')[0]}{arrow}"
            else:
                new_text = current_text.split(' ')[0]  # Remove any existing arrows
            header.model().setHeaderData(i, QtCore.Qt.Horizontal, new_text, QtCore.Qt.DisplayRole)

    def show_context_menu(self, position):
        """Show context menu for the selected item."""
        item = self.itemAt(position)
        if item is None:
            return

        menu = QtWidgets.QMenu()
        rename_action = menu.addAction("Rename Function")
        set_breakpoint_action = menu.addAction("Set Breakpoint")
        add_comment_action = menu.addAction("Add Comment")

        action = menu.exec_(self.viewport().mapToGlobal(position))
        if action == rename_action:
            self.rename_function(item)
        elif action == set_breakpoint_action:
            self.set_breakpoint(item)
        elif action == add_comment_action:
            self.add_comment(item)

    def rename_function(self, item):
        """Rename the selected function."""
        addr = int(item.text(1), 16)
        old_name = item.text(0)
        new_name, ok = QtWidgets.QInputDialog.getText(self, "Rename Function", "New function name:", text=old_name)
        if ok and new_name:
            idc.set_name(addr, new_name)
            item.setText(0, new_name)

    def set_breakpoint(self, item):
        """Set a breakpoint on the selected function."""
        addr = int(item.text(1), 16)
        idc.add_bpt(addr)

    def add_comment(self, item):
        """Add a comment to the selected function."""
        addr = int(item.text(1), 16)
        comment, ok = QtWidgets.QInputDialog.getText(self, "Add Comment", "Enter comment:")
        if ok and comment:
            idc.set_cmt(addr, comment, 0)

class FunctionsPlus(idaapi.PluginForm):
    """Functions+ plugin."""

    def __init__(self):
        super(FunctionsPlus, self).__init__()
        self.tree = None
        self.icon = 135
        self.show_extra_fields = False
        self.cols = Cols(self.show_extra_fields)
        self.search_bar = None
        self.settings = self.load_settings()

    def OnCreate(self, form):
        """Called when the plugin form is created."""
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()

        # Add search bar
        self.search_bar = QtWidgets.QLineEdit()
        self.search_bar.setPlaceholderText("Search functions...")
        self.search_bar.textChanged.connect(self.filter_functions)
        layout.addWidget(self.search_bar)

        # Create tree widget
        self.tree = SortableTreeWidget()
        self.tree.setColumnCount(len(self.cols.names))
        self.tree.setHeaderLabels(self.cols.names)
        self.tree.itemDoubleClicked.connect(self._dblclick)
        layout.addWidget(self.tree)

        # Add export button
        export_button = QtWidgets.QPushButton("Export to CSV")
        export_button.clicked.connect(self.export_to_csv)
        layout.addWidget(export_button)

        self._populate_tree()

        self.tree.setColumnWidth(0, 512)
        for index in range(6, len(self.cols.names)):
            self.tree.setColumnWidth(index, 32)
        self.tree.setAlternatingRowColors(True)

        self.parent.setLayout(layout)
        self.restore_ui_state()

    def OnClose(self, form):
        """Called when the plugin form is closed."""
        self.save_ui_state()

    def Show(self):
        """Creates the form if not created or focuses it if it was."""
        return idaapi.PluginForm.Show(self, 'Functions+')

    def _populate_tree(self):
        """Populates functions tree."""
        self.tree.clear()
        self._build_tree(FunctionsTree().get(), self.tree)

    def _build_tree(self, function_tree, root):
        """Builds Qt Widget tree."""
        if not function_tree:
            return

        if isinstance(function_tree, FunctionData):
            self._handle_function_data_instance(function_tree, root)
            return

        for name, tree in sorted(function_tree.items()):
            func_item = QtWidgets.QTreeWidgetItem(root)
            if not isinstance(tree, FunctionData):
                name = self._handle_class_name(tree, name, func_item)
            func_item.setText(0, name)
            self._build_tree(tree, func_item)

    def _handle_class_name(self, tree, name, func_item):
        """Handles class name."""
        tree_keys_len = len(list(tree.keys()))
        name = f'{name} ({tree_keys_len} {self._get_word(tree_keys_len)})'
        font = QtGui.QFont()
        font.setBold(True)
        func_item.setFont(0, font)
        return name

    def _handle_function_data_instance(self, function_tree, root):
        """Handles FunctionData instance."""
        flags = int(function_tree.flags)
        addr = function_tree.addr

        self.cols.set_data(addr, flags)

        for index in range(len(self.cols.names)):
            if index > 0:
                root.setText(index, self.cols.item(index))
            if flags & idc.FUNC_THUNK:
                root.setBackground(index, QtGui.QColor('#E8DAEF'))
            if flags & idc.FUNC_LIB:
                root.setBackground(index, QtGui.QColor('#D1F2EB'))

    @staticmethod
    def _get_word(len):
        """Gets proper word for number."""
        return "item" if len % 10 == 1 and len % 100 != 11 else "items"

    def _dblclick(self, item):
        """Handles double click event."""
        try:
            idaapi.jumpto(int(item.text(1), 16))
        except ValueError:
            pass

    def filter_functions(self):
        """Filters functions based on search text."""
        search_text = self.search_bar.text().lower()
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i), search_text)

    def _filter_item(self, item, search_text):
        """Recursively filters items in the tree."""
        should_show = search_text in item.text(0).lower()
        
        for i in range(item.childCount()):
            child_visible = self._filter_item(item.child(i), search_text)
            should_show = should_show or child_visible

        item.setHidden(not should_show)
        return should_show

    def export_to_csv(self):
        """Export the function list to a CSV file."""
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Save CSV", "", "CSV Files (*.csv)")
        if filename:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(self.cols.names)  # Write header
                self._write_tree_to_csv(self.tree.invisibleRootItem(), writer)

    def _write_tree_to_csv(self, item, writer):
        """Recursively write tree items to CSV."""
        for i in range(item.childCount()):
            child = item.child(i)
            if child.childCount() == 0:  # It's a leaf node (function)
                row = [child.text(j) for j in range(self.tree.columnCount())]
                writer.writerow(row)
            else:
                self._write_tree_to_csv(child, writer)

    def load_settings(self):
        """Load plugin settings from IDA database."""
        settings = idaapi.get_plugin_options("FunctionsPlus")
        return json.loads(settings) if settings else {}

    def save_settings(self):
        """Save plugin settings to IDA database."""
        idaapi.set_plugin_options("FunctionsPlus", json.dumps(self.settings))

    def save_ui_state(self):
        """Save UI state (column widths, sort settings) to settings."""
        self.settings['column_widths'] = [self.tree.columnWidth(i) for i in range(self.tree.columnCount())]
        self.settings['sort_column'] = self.tree.current_sort_column
        self.settings['sort_order'] = int(self.tree.current_sort_order)
        self.settings['window_geometry'] = self.parent.saveGeometry().toHex().decode()
        self.save_settings()

    def restore_ui_state(self):
        """Restore UI state from settings."""
        if 'column_widths' in self.settings:
            for i, width in enumerate(self.settings['column_widths']):
                self.tree.setColumnWidth(i, width)
        if 'sort_column' in self.settings and 'sort_order' in self.settings:
            self.tree.sortItems(self.settings['sort_column'], self.settings['sort_order'])
        if 'window_geometry' in self.settings:
            self.parent.restoreGeometry(QtCore.QByteArray.fromHex(self.settings['window_geometry'].encode()))

class FunctionsPlusPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Functions+"
    help = "Enhanced version of functions window with improved functionality"
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