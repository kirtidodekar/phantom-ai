import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

/**
 * ErrorBoundary — prevents a render fault in any single dashboard view from
 * blanking the whole console. Catches the error, reports it, and offers a
 * local recovery path so the analyst can keep working in other tabs.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('[sentinel-ui] render error:', error, info?.componentStack);
  }

  componentDidUpdate(prevProps) {
    // Clear the fault when the operator navigates to a different view.
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="soc-surface p-6 border border-rose-200 bg-rose-50 space-y-3 animate-fadeIn" role="alert">
        <div className="flex items-start gap-3">
          <span className="rounded-lg bg-rose-100 p-2 shrink-0">
            <AlertTriangle className="w-5 h-5 text-rose-700" />
          </span>
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-slate-900">This view failed to render</h2>
            <p className="text-xs text-slate-600 mt-1 leading-relaxed">
              The rest of the console is still operational. Switch tabs to continue working, or retry this view.
            </p>
            <pre className="mt-2 max-h-32 overflow-auto rounded-lg border border-rose-200 bg-white p-2.5 text-[11px] font-mono text-rose-800 whitespace-pre-wrap">
              {String(error?.message || error)}
            </pre>
          </div>
        </div>
        <button
          type="button"
          onClick={() => this.setState({ error: null })}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold transition"
        >
          <RotateCcw className="w-3.5 h-3.5 text-blue-600" />
          <span>Retry view</span>
        </button>
      </div>
    );
  }
}
