def main(argv=None):
    from hashcathelper.args import parse_args
    from hashcathelper.log import init_logging
    args = parse_args(argv=argv)
    init_logging(loglevel=args.log_level)
    args.func(args)


if __name__ == "__main__":
    main()
