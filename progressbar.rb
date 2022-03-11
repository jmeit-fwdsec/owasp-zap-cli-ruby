require 'io/console'

module ProgressBar
    class ProgressBar

        def initialize( output: $stdout, percent: 0 )
            @output = output
            @content = ''
            @time_start = Time.now
            @pct = percent
            @meta = ''
            display
        end

        def clear
            @output.print "\r#{' '*terminal_width}"
            @output.flush
        end

        def terminal_width
            begin
                $stdout.winsize[1]
            rescue
                100
            end
        end

        def time_display
            elapsed_t = Time.at( Time.now - @time_start ).utc
            "Elapsed: #{elapsed_t.strftime '%H:%M:%S'}"
        end

        def pct_display
            "[#{@pct}%]"
        end

        def eol
            @pct == 100 ? "\n" : ''
        end

        def progressbar
            bar_begin = '|'
            bar_end = '|'
            padding = 10
            progress_width = terminal_width - time_display.length - bar_begin.length - bar_end.length - pct_display.length - @meta.length - padding
            progress_markers = '=' * (progress_width * (@pct/100)).round
            bar = "#{bar_begin}#{progress_markers}#{'-' * (progress_width-progress_markers.length)}#{bar_end}"
            mid_pct bar
        end

        def mid_pct( bar )
            insert_at = bar.length/2 - pct_display.length/2
            bar_a = bar.split('')
            pct_display.split('').each.with_index do |_char,i|
                bar_a[i + insert_at] = pct_display[i]
            end
            bar_a.join
        end

        def display
            @content = "#{time_display} #{progressbar} #{@meta}#{eol}"

            clear
            @output.print "\r#{@content}"
            @output.flush
        end

        def update( percent )
            percent = percent.to_i > 100 ? 100 : percent.to_f.round(2)
            @pct = percent
            display
        end

        def progress
            @pct
        end

        def meta( meta )
            @meta = meta.to_s
        end

    end
end
