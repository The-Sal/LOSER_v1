"""Interactive UI for managing machine audit configuration."""
import os
import json
from typing import Dict, Any, Optional, List, Tuple


class MachineConfigUI:
    """Interactive terminal UI for managing machine configuration."""

    def __init__(self):
        """Initialize the UI with the machine config."""
        self.config_path = os.path.join(os.getcwd(), 'machine_config.json')
        self.config = self.load_config()
        self.keys_list: List[str] = []  # Ordered list of keys for index-based access

    def load_config(self) -> Dict[str, Any]:
        """Load the machine configuration from file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {}

    def save_config(self) -> None:
        """Save the machine configuration to file."""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        print("✓ Config saved - server will reload on next audit request")

    def update_keys_list(self) -> None:
        """Update the ordered list of keys for index-based access."""
        self.keys_list = list(self.config.keys())

    def display_config(self) -> None:
        """Display the current machine configuration in a formatted way."""
        print("\n" + "=" * 80)
        print("CURRENT MACHINE CONFIGURATION")
        print("=" * 80)
        self.update_keys_list()

        if not self.config:
            print("No entries found.")
        else:
            for idx, key in enumerate(self.keys_list, 1):
                entry = self.config[key]
                print(f"\n[{idx}] {entry.get('name', key)}")
                print(f"    Description: {entry.get('description', 'N/A')}")
                print(f"    Filepath: {entry.get('filepath', 'N/A')}")
        print("=" * 80 + "\n")

    def add_entry(self) -> None:
        """Add a new machine config entry."""
        print("\n--- ADD NEW ENTRY ---")
        key = input("Enter unique key (e.g., 'Dart Server'): ").strip()

        if key in self.config:
            print(f"❌ Error: Key '{key}' already exists.")
            return

        name = input("Enter name: ").strip()
        description = input("Enter description: ").strip()
        filepath = input("Enter filepath: ").strip()

        if not filepath:
            print("❌ Error: Filepath is required.")
            return

        self.config[key] = {
            'name': name or key,
            'description': description,
            'filepath': filepath
        }
        self.save_config()

    def update_entry(self) -> None:
        """Update an existing machine config entry by index."""
        self.display_config()
        if not self.config:
            return

        print("--- UPDATE ENTRY ---")
        try:
            idx_input = input("Enter the index number to update: ").strip()
            idx = int(idx_input) - 1

            if idx < 0 or idx >= len(self.keys_list):
                print(f"❌ Error: Invalid index. Please enter a number between 1 and {len(self.keys_list)}.")
                return

            key = self.keys_list[idx]
        except ValueError:
            print("❌ Error: Please enter a valid number.")
            return

        entry = self.config[key]
        print(f"\nCurrent values for '{entry.get('name', key)}':")
        print(f"  Name: {entry.get('name', 'N/A')}")
        print(f"  Description: {entry.get('description', 'N/A')}")
        print(f"  Filepath: {entry.get('filepath', 'N/A')}")

        print("\nLeave blank to keep current value.")
        name = input("New name (press Enter to skip): ").strip()
        description = input("New description (press Enter to skip): ").strip()
        filepath = input("New filepath (press Enter to skip): ").strip()

        if name:
            entry['name'] = name
        if description:
            entry['description'] = description
        if filepath:
            entry['filepath'] = filepath

        self.save_config()

    def remove_entry(self) -> None:
        """Remove a machine config entry by index."""
        self.display_config()
        if not self.config:
            return

        print("--- REMOVE ENTRY ---")
        try:
            idx_input = input("Enter the index number to remove: ").strip()
            idx = int(idx_input) - 1

            if idx < 0 or idx >= len(self.keys_list):
                print(f"❌ Error: Invalid index. Please enter a number between 1 and {len(self.keys_list)}.")
                return

            key = self.keys_list[idx]
        except ValueError:
            print("❌ Error: Please enter a valid number.")
            return

        entry_name = self.config[key].get('name', key)
        confirm = input(f"Remove '{entry_name}'? (y/n): ").strip().lower()

        if confirm in ('y', 'yes'):
            del self.config[key]
            self.save_config()
        else:
            print("Removal cancelled.")

    def run(self) -> None:
        """Run the interactive configuration UI."""
        print("\n" + "=" * 80)
        print("MACHINE AUDIT CONFIGURATION MANAGER")
        print("Server is running in the background on port 9631")
        print("=" * 80)

        while True:
            print("\nMENU:")
            print("  [1] View configuration")
            print("  [2] Add entry")
            print("  [3] Update entry (by index)")
            print("  [4] Remove entry (by index)")
            print("  [5] Exit")

            choice = input("\nSelect an option (1-5): ").strip()

            if choice == '1':
                self.display_config()
            elif choice == '2':
                self.add_entry()
            elif choice == '3':
                self.update_entry()
            elif choice == '4':
                self.remove_entry()
            elif choice == '5':
                print("Exiting configuration manager. Server continues running in background.")
                break
            else:
                print("❌ Invalid option. Please try again.")
