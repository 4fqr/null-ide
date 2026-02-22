# Quick Setup Guide

## First Time Setup

Follow these steps to get Null IDE running:

### 1. Install Dependencies

```powershell
npm install
```

This will install all required packages including:
- Electron
- React & ReactDOM
- TypeScript
- Monaco Editor
- Vite
- Zustand (state management)
- And all development dependencies

### 2. Important: Icon File

Make sure `null-ide.ico` is present in the root directory. This is your application icon and is referenced throughout the codebase.

### 3. Start Development Server

```powershell
npm run dev
```

This command will:
1. Start the Vite development server on port 5173
2. Wait for the server to be ready
3. Launch the Electron application
4. Enable hot module replacement for rapid development

### 4. What to Expect

When the app launches, you'll see:
- **Top Bar**: Null IDE branding, file tabs, settings and about buttons
- **Left Sidebar**: File Explorer, Hacking Tools, and Programmer Utilities
- **Main Area**: Monaco Editor with the Welcome tab
- **Right Sidebar**: DeepHat AI embedded browser
- **Status Bar**: Privacy indicator, language mode, version

### 5. Try These Features

#### Opening Files
1. Click "Open Folder" in the File Explorer panel
2. Navigate to any project folder
3. Click on files to open them in the editor

#### Using Tools
1. Click "Hacking Tools" in the left sidebar
2. Expand any category
3. Click a tool to run it
4. Results appear in the output panel

#### Trying Utilities
1. Click "Programmer Utilities" in the left sidebar
2. Browse the extensive collection of text transformations, converters, and generators
3. Each tool has a description of what it does

#### Settings
- Press `Ctrl+,` or click the ⚙️ icon in the top bar
- Customize font size, tab size, and privacy preferences

### 6. Building for Production

When ready to create a distributable version:

```powershell
# Build the application
npm run build

# Package for distribution
npm run package
```

The packaged application will be in the `release/` directory.

## Troubleshooting

### Port 5173 Already in Use
If you see an error about port 5173, either:
- Stop the process using that port
- Change the port in `vite.config.ts`

### Dependencies Not Installing
Try:
```powershell
npm cache clean --force
npm install
```

### TypeScript Errors in Editor
The TypeScript errors showing in the file list are expected until dependencies are installed. They will disappear after running `npm install`.

### Electron Window Not Opening
Make sure:
1. The Vite dev server started successfully
2. You see "Running at http://localhost:5173"
3. Try running `npm run dev` again

### DeepHat Sidebar Not Loading
The DeepHat AI sidebar loads https://deephat.ai. If it doesn't load:
- Check your internet connection
- The site may be temporarily unavailable
- You can still use all other features offline

## Development Tips

### Hot Reload
- Changes to React components will hot-reload automatically
- Changes to main process files require restarting the app
- Changes to CSS will update instantly

### Adding New Tools
- Edit `src/renderer/src/components/panels/HackingTools.tsx` for security tools
- Edit `src/renderer/src/components/panels/ProgrammerUtilities.tsx` for utilities
- Follow the existing pattern for consistency

### Modifying Theme
- All theme variables are in `src/renderer/src/styles/global.css`
- Change CSS variables to customize colors, fonts, spacing

### State Management
- Global state is managed with Zustand in `src/renderer/src/store/store.ts`
- Add new state and actions following the existing pattern

## Next Steps

1. Install dependencies: `npm install`
2. Start the app: `npm run dev`
3. Explore the features
4. Customize to your needs
5. Share with the community!

## Need Help?

- Check the main README.md for detailed documentation
- Review the code comments for implementation details
- Open an issue if you encounter problems

Happy hacking! 🔐⚡
