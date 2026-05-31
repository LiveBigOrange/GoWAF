(function() {
    function create(config) {
        var autoRefresh = config.autoRefresh || null;
        var onExpand = config.onExpand || function() {};
        var onCollapse = config.onCollapse || function() {};

        var expandedIds = new Set();
        var PAUSE_REASON = 'detail-viewing';

        function expand(detailId) {
            expandedIds.add(detailId);
            if (autoRefresh) {
                autoRefresh.pause(PAUSE_REASON);
            }
            onExpand(detailId);
        }

        function collapse(detailId) {
            expandedIds.delete(detailId);
            if (expandedIds.size === 0 && autoRefresh) {
                autoRefresh.resume(PAUSE_REASON);
            }
            onCollapse(detailId);
        }

        function toggle(detailId) {
            if (expandedIds.has(detailId)) {
                collapse(detailId);
            } else {
                expand(detailId);
            }
        }

        function isExpanded(detailId) {
            return expandedIds.has(detailId);
        }

        function getExpandedIds() {
            return new Set(expandedIds);
        }

        function hasExpanded() {
            return expandedIds.size > 0;
        }

        function collapseAll() {
            expandedIds.clear();
            if (autoRefresh) {
                autoRefresh.resume(PAUSE_REASON);
            }
        }

        return {
            expand: expand,
            collapse: collapse,
            toggle: toggle,
            isExpanded: isExpanded,
            getExpandedIds: getExpandedIds,
            hasExpanded: hasExpanded,
            collapseAll: collapseAll,
            destroy: function() {
                expandedIds.clear();
                if (autoRefresh) {
                    autoRefresh.resume(PAUSE_REASON);
                }
            }
        };
    }

    window.LogDetailManager = { create: create };
})();
